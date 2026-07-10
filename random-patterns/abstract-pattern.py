import turtle as t
import colorsys as cs
import math
import time
t.setup(800,800)
t.bgcolor("black")
t.speed(0)
t.width(2)
t.tracer(0)
t.hideturtle()
t.penup()
t.goto(0,0)
t.pendown()
layers=36
petals=24
radius=260
steps1=layers*petals*4
delay1=5/steps1
step_count=0
for j in range(layers):
    hue=j/layers
    t.color(cs.hsv_to_rgb(hue,1,1))
    for i in range(petals):
        t.circle(radius-j*6,60)
        t.left(120)
        t.circle(radius-j*6,60)
        t.right(180)
        t.left(360/petals)
        step_count+=1
        t.update()
        time.sleep(delay1)
    t.right(10)
t.width(1)
steps2=200
delay2=3/steps2
for i in range(200):
    t.color(cs.hsv_to_rgb(i/200,1,1))
    t.forward(i*0.6)
    t.left(59)
    t.update()
    time.sleep(delay2)
t.penup()
t.goto(0,0)
t.pendown()
t.width(2)
steps3=72
delay3=2/steps3
for i in range(72):
    t.color(cs.hsv_to_rgb(i/72,1,1))
    t.forward(300)
    t.backward(300)
    t.left(5)
    t.update()
    time.sleep(delay3)
t.done()