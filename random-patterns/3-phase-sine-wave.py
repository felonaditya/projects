import turtle
import math
import time
screen=turtle.Screen()
screen.bgcolor("black")
screen.setup(width=800,height=600)
screen.tracer(0)
wave_turtle=turtle.Turtle()
wave_turtle.speed(0)
wave_turtle.hideturtle()
amplitude=100
frequency=0.02
phase_shift=0
running=True
def on_close():
    global running
    running=False
screen.getcanvas().winfo_toplevel().protocol("WM_DELETE_WINDOW",on_close)
while running:
    wave_turtle.clear()
    wave_turtle.penup()
    wave_turtle.color("#FFFFFF")
    wave_turtle.pensize(3)
    start_x,start_y=-390,amplitude*math.sin(frequency*-390+phase_shift)
    wave_turtle.goto(start_x,start_y)
    wave_turtle.pendown()
    for x in range(-390,391,2):
        y=amplitude*math.sin(frequency*x+phase_shift)
        wave_turtle.goto(x,y)
    wave_turtle.penup()
    wave_turtle.color("#40E0D0")
    start_y=amplitude*math.sin(frequency*-390+phase_shift+(math.pi*2/3))
    wave_turtle.goto(start_x,start_y)
    wave_turtle.pendown()
    for x in range(-390,391,2):
        y=amplitude*math.sin(frequency*x+phase_shift+(math.pi*2/3))
        wave_turtle.goto(x,y)
    wave_turtle.penup()
    wave_turtle.color("#800080")
    start_y=amplitude*math.sin(frequency*-390+phase_shift+(math.pi*4/3))
    wave_turtle.goto(start_x,start_y)
    wave_turtle.pendown()
    for x in range(-390,391,2):
        y=amplitude*math.sin(frequency*x+phase_shift+(math.pi*4/3))
        wave_turtle.goto(x,y)
    phase_shift+=0.15
    screen.update()
    time.sleep(0.03)
screen.bye()