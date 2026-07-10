import turtle as tur
import colorsys as cs
import time
tur.setup(800,800)
tur.setworldcoordinates(-500,-500,500,500)
tur.speed(0)
tur.tracer(0)
tur.width(2)
tur.bgcolor("black")
tur.hideturtle()
steps=25*15
delay=7/steps
for j in range(25):
    for i in range(15):
        tur.color(cs.hsv_to_rgb(i/15,0.4+0.6*j/25,0.8+0.2*j/25))
        tur.right(90)
        tur.circle(200-j*4,90)
        tur.left(90)
        tur.circle(200-j*4,90)
        tur.right(180)
        tur.circle(50,24)
        tur.update()
        time.sleep(delay)
tur.done()