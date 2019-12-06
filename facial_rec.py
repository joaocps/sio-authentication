import face_recognition
import cv2


class FaceRecognition(object):

    def __init__(self):
        self.video_capture = cv2.VideoCapture(0)
        self.server_images = "/home/user/Desktop/Project3-first/server-imgs"

    def take_picture(self):
        while True:

            ret, frame = self.video_capture.read()
            cv2.imshow('Myface', frame)

            if cv2.waitKey(1) & 0xFF == ord('\r'):
                rgb_frame = frame[:, :, ::-1]
                # self.takepicture_and_recognize(frame, rgb_frame, known_face_encodings, known_face_names)
                self.video_capture.release()
                cv2.destroyAllWindows()

                return rgb_frame, frame
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("EXIT")
                break
