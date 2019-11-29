import asyncio
import getpass
import json
import base64
import argparse
import coloredlogs
import logging
import os
import time
from default_crypto import Asymmetric, Symmetric
from citizen_card import CitizenCard

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3

# GLOBAL
crypto_dir = './client-keys'


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.shared = None
        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.asymmetric_encrypt = Asymmetric()
        self.symmetric = Symmetric()

        try:
            self.citizen_card = CitizenCard()
        except:
            logger.error("Citizen card reader probably not connected! Exiting ...")
            exit(1)

        self.symmetric_cypher = None
        self.cypher_mode = None
        self.synthesis_algorithm = None

        self._public_key = None
        self._private_key = None
        self.server_pub = None
        self.password = None

    def handshake(self):

        logger.info("Introduce password to generate rsa key: ")
        self.password = getpass.getpass('Password:')

        if not os.path.exists("client-keys"):
            try:
                os.mkdir("client-keys")
                self._private_key, self._public_key = self.asymmetric_encrypt.generate_rsa_keys(crypto_dir, "client",
                                                                                                self.password)
            except:
                logger.exception("Unable to create storage directory")
        else:
            self._private_key, self._public_key = self.asymmetric_encrypt.generate_rsa_keys(crypto_dir, "client",
                                                                                            self.password)

        symmetric_cypher = int(input("Symmetric Cypher ( aes128(1), 3des(2) or chacha20(3) ): "))
        cypher_mode = int(input("Cypher mode ( cbc(1) or ctr(2) ): "))
        synthesis_algorithm = int(input("Synthesis Algorithm ( sha-256(1) or sha-512(2) )"))

        if symmetric_cypher < 1 or symmetric_cypher > 3:
            logger.error("Symmetric Cypher not allowed, try again!")
            self.handshake()
        elif cypher_mode < 1 or cypher_mode > 2:
            logger.error("Cypher mode not allowed, try again!")
            self.handshake()
        elif synthesis_algorithm < 1 or synthesis_algorithm > 2:
            logger.error("Synthesis Algorithm not allowed, try again!")
            self.handshake()

        return symmetric_cypher, cypher_mode, synthesis_algorithm

    def veritfy_card_connection(self):
        try:
            logger.info(self.citizen_card.get_name())
        except Exception:
            logger.error("CITIZEN CARD PROBABLY NOT CONNECTED")
            exit(1)

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')

        citizen_name = self.veritfy_card_connection()

        # GET CC pubkey
        publickeycc = self.citizen_card.get_public_key()
        print(self.citizen_card.serialize(publickeycc))

        # GET CC privkey
        print(self.citizen_card.get_private_key())


        self.symmetric_cypher, self.cypher_mode, self.synthesis_algorithm = self.handshake()

        print(self._public_key)
        message = {'type': 'OPEN',
                   'file_name': self.file_name,
                   'symmetric_cypher': self.symmetric_cypher,
                   'cypher_mode': self.cypher_mode,
                   'synthesis_algorithm': self.synthesis_algorithm,
                   # É SUPOSTO ENVIAR ASSIM (str) A PUB KEY?
                   'client_public_key': self._public_key.decode()
                   }
        self._send(message)

        logger.info(message)

        self.state = STATE_OPEN

    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        if self.state == STATE_OPEN:
            data = self.symmetric.handshake_decrypt(data)
            # logger.debug('DEBUG: Decrypt: ', data)
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        # logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.server_pub = self.asymmetric_encrypt.load_pub_from_str(message["server_pub_key"].encode())
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')

        if os.path.exists("client-keys"):
            os.remove("client-keys/" + 'client_private_rsa.pem')
            os.remove("client-keys/" + 'client_public_rsa.pem')

        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """
        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60

            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """

        message_b = (json.dumps(message) + '\r\n').encode()
        if self.state == STATE_CONNECT:
            message_b = self.symmetric.handshake_encrypt(message_b)
        else:
            message_b = self.symmetric.encrypt(self.symmetric_cypher, message_b, self.synthesis_algorithm,
                                               self.cypher_mode,
                                               pkey=self.server_pub)
        self.transport.write(message_b)

        # Este sleep é um workaround para os blocos/pacotes perdidos ou incompletos
        time.sleep(0.05)


def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


if __name__ == '__main__':
    main()
