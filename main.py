import os
from public.logo import logo
from public.features import features
import speech_recognition as sr
from colorama import Style, Fore
from app.agents.genai_agent import start_agent_flow
from app.settings.settings import USER_NAME

# Set environment variables to reduce log verbosity
os.environ['ALSA_LOG_LEVEL'] = '0'
os.environ['JACK_LOG_LEVEL'] = '0'

# Redirect file descriptor 2 (stderr) to /dev/null so native logs are suppressed
devnull_fd = os.open(os.devnull, os.O_WRONLY)
os.dup2(devnull_fd, 2)

# Handle user requests
def handle_user_requests(recognized_text):
    try:
        # Call the agent flow function
        start_agent_flow(query=recognized_text)
    except :
        pass

# Main function
def main():
    recognizer = sr.Recognizer()
    mic = sr.Microphone(device_index=3)
    recognizer.energy_threshold = 200
    recognizer.pause_threshold = 0.8

    # Adjust for ambient noise once at startup
    with mic as source:
        recognizer.adjust_for_ambient_noise(source, duration=1)

    # Display the logo and features
    print(logo)
    print(features)

    # Main loop: listen, process when user stops speaking, then resume listening
    while True:
        try:
            with mic as source:
                audio = recognizer.listen(source)
            try:
                recognized_text = recognizer.recognize_google(audio)
                print(f"{Style.BRIGHT}{Fore.YELLOW}{USER_NAME}:{Fore.RESET}{Style.RESET_ALL} {recognized_text}")
                handle_user_requests(recognized_text)
            except sr.UnknownValueError:
                continue
            except sr.RequestError as e:
                print("Error from the speech recognition service:", e)
                continue

        # Exit the app
        except KeyboardInterrupt:
            print("\nExiting program.")
            break

# Start the main function
if __name__ == "__main__":
    main()
