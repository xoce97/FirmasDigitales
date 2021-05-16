import time

## Define a static Pomodoro timer.
def Countdown():
    p = 3.00
    alarm = time.time() + p
    while True: ## Loop infinitely
        n = time.time()
        if not n < alarm:
            print("Time's up!")
            break

Countdown()