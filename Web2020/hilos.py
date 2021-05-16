import threading
import time
#https://pymotw.com/2/threading/

## Define a static Pomodoro timer.
def Countdown():
    p = 10.00
    alarm = time.time() + p
    while True: ## Loop infinitely
        n = time.time()
        if n < alarm:
            print(round(alarm - n))
        else:
            print("Time's up!")
            break

t = threading.Thread(target=Countdown)
t.start()