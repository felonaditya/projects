import math
import random
import turtle
def setup_screen():
    screen = turtle.Screen()
    screen.bgcolor("black")
    screen.setup(width=800, height=800)
    screen.title("Aesthetic Generative Mandala")
    screen.tracer(0, 0)
    return screen
def get_random_palette():
    palettes = [
        ["#00f5d4", "#7b2cbf", "#9d4edd", "#e0aaff"],
        ["#ff007f", "#ffaa00", "#ff00aa", "#ff5500"],
        ["#00b4d8", "#0077b6", "#90e0ef", "#caf0f8"],
        ["#70e000", "#38b000", "#007200", "#ccff33"],
    ]
    return random.choice(palettes)
def draw_aesthetic_pattern():
    t = turtle.Turtle()
    t.speed(0)
    t.hideturtle()
    colors = get_random_palette()
    num_petals = random.randint(6, 12)
    layers = 180
    frequency = random.choice([2, 3, 4, 5])
    wave_amplitude = random.randint(20, 50)
    for i in range(layers):
        t.color(colors[i % len(colors)])
        angle_rad = math.radians(i * (360 / layers) * frequency)
        dynamic_radius = 150 + math.sin(angle_rad) * wave_amplitude
        t.penup()
        t.goto(0, 0)
        t.pendown()        
        t.setheading(i * (360 / layers) * (num_petals / 2))
        t.forward(dynamic_radius)
        t.right(45)
        t.forward(dynamic_radius / 3)
        t.circle(5, steps=4)
    turtle.update()
if __name__ == "__main__":
    screen = setup_screen()
    draw_aesthetic_pattern()
    screen.exitonclick()