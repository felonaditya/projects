import numpy as np
import matplotlib.pyplot as plt
from matplotlib.widgets import TextBox
from matplotlib.animation import FuncAnimation
from matplotlib.ticker import FuncFormatter
import warnings
warnings.filterwarnings("ignore")

plt.rcParams['toolbar'] = 'none'

# Constants
C = 2.99792458e8
H = 6.62607015e-34
AU = 1.495978707e11
LIGHT_YEAR = 9.4607304725808e15

def wl_to_freq(wl_nm):
    return C / (wl_nm * 1e-9)

def format_frequency(freq_hz):
    """Formats raw Hz into clean, human-readable units."""
    if freq_hz >= 1e12:
        return f"{freq_hz / 1e12:.4f} THz"
    elif freq_hz >= 1e9:
        return f"{freq_hz / 1e9:.4f} GHz"
    elif freq_hz >= 1e6:
        return f"{freq_hz / 1e6:.4f} MHz"
    elif freq_hz >= 1e3:
        return f"{freq_hz / 1e3:.4f} kHz"
    else:
        return f"{freq_hz:.4f} Hz"

def get_spatial_scale(max_meters):
    """Determines the best unit and scaling factor for a given distance in meters."""
    if max_meters >= LIGHT_YEAR * 0.1:
        return LIGHT_YEAR, "light-years"
    elif max_meters >= AU * 0.1:
        return AU, "AU"
    elif max_meters >= 1000.0:
        return 1000.0, "km"
    elif max_meters >= 1.0:
        return 1.0, "meters"
    elif max_meters >= 0.01:
        return 0.01, "cm"
    elif max_meters >= 0.001:
        return 0.001, "mm"
    elif max_meters >= 1e-6:
        return 1e-6, "µm"
    else:
        return 1e-9, "nm"

def wavelength_to_rgb_cie(wl_nm):
    """
    Converts a wavelength in nm to an ultra-realistic sRGB color 
    using analytical approximations of the CIE 1931 color matching functions.
    """
    wl = float(wl_nm)
    if wl < 380.0 or wl > 780.0:
        return (0.0, 0.0, 0.0)
    
    x1 = 1.056 * np.exp(-0.5 * ((wl - 599.8) / 37.9)**2)
    x2 = 0.362 * np.exp(-0.5 * ((wl - 442.0) / 16.0)**2)
    x3 = -0.065 * np.exp(-0.5 * ((wl - 501.1) / 20.4)**2)
    X = max(0.0, x1 + x2 + x3)

    Y = 0.821 * np.exp(-0.5 * ((wl - 568.8) / 46.9)**2) + 0.286 * np.exp(-0.5 * ((wl - 530.9) / 16.3)**2)
    Z = 1.217 * np.exp(-0.5 * ((wl - 437.0) / 11.8)**2) + 0.681 * np.exp(-0.5 * ((wl - 459.0) / 26.0)**2)

    r_lin =  3.2404542 * X - 1.5371385 * Y - 0.4985314 * Z
    g_lin = -0.9692660 * X + 1.8760108 * Y + 0.0415560 * Z
    b_lin =  0.0556434 * X - 0.2040259 * Y + 1.0572252 * Z

    r_lin, g_lin, b_lin = max(0.0, r_lin), max(0.0, g_lin), max(0.0, b_lin)

    if wl < 420.0:
        factor = 0.3 + 0.7 * (wl - 380.0) / (420.0 - 380.0)
    elif wl > 700.0:
        factor = 0.3 + 0.7 * (780.0 - wl) / (780.0 - 700.0)
    else:
        factor = 1.0

    r_lin *= factor
    g_lin *= factor
    b_lin *= factor

    def gamma_correct(val):
        return 12.92 * val if val <= 0.0031308 else 1.055 * (val ** (1.0 / 2.4)) - 0.055

    r = min(1.0, max(0.0, gamma_correct(r_lin)))
    g = min(1.0, max(0.0, gamma_correct(g_lin)))
    b = min(1.0, max(0.0, gamma_correct(b_lin)))

    max_val = max(r, g, b)
    if max_val > 0:
        boost = 1.0 / (max_val ** 0.1)
        r, g, b = min(1.0, r * boost), min(1.0, g * boost), min(1.0, b * boost)

    return (r, g, b)

# ==================== Figure & Center Window Setup ====================
fig_w, fig_h = 1200, 800
fig = plt.figure(figsize=(fig_w / 100, fig_h / 100), facecolor='#0a0a0a')

# Pure graphical environment extraction - avoids building temporary master instances
try:
    mngr = plt.get_current_fig_manager()
    if hasattr(mngr, 'window'):
        # Tkinter native window backend sizing wrapper
        if hasattr(mngr.window, 'winfo_screenwidth'):
            screen_w = mngr.window.winfo_screenwidth()
            screen_h = mngr.window.winfo_screenheight()
            x = (screen_w - fig_w) // 2
            y = (screen_h - fig_h) // 2
            mngr.window.wm_geometry(f"{fig_w}x{fig_h}+{x}+{y}")
        # Qt system sizing configuration wrapper
        elif hasattr(mngr.window, 'setGeometry'):
            # Grab desktop size natively without triggering a separate thread
            geom = plt.get_current_fig_manager().canvas.manager.window.screen().geometry()
            x = (geom.width() - fig_w) // 2
            y = (geom.height() - fig_h) // 2
            mngr.window.setGeometry(x, y, fig_w, fig_h)
except Exception:
    pass

# ==================== Layout Coordinates ====================
ax_wave = fig.add_axes([0.08, 0.44, 0.78, 0.51], facecolor='#111111')

ax_wl_box = fig.add_axes([0.36, 0.23, 0.28, 0.05])
text_wl = TextBox(ax_wl_box, 'Wavelength (nm)  ', initial="380")

text_wl.label.set_color('white')
text_wl.label.set_fontsize(11)
try:
    text_wl.text_disp.set_color('black')
    text_wl.text_disp.set_fontsize(11)
except:
    pass

ax_info = fig.add_axes([0.08, 0.04, 0.78, 0.12], facecolor='#111111')
ax_info.axis('off')

current_wl = 380
wave_line = None
core_line = None

def setup_axes(wavelength_m):
    total_length = 8 * wavelength_m
    scale_factor, unit_name = get_spatial_scale(total_length)
    
    ax_wave.grid(True, color='#262626', linestyle='--', alpha=0.6)
    ax_wave.set_xlabel(f'Position along propagation ({unit_name})', color='#cccccc', fontsize=12)
    ax_wave.set_ylabel('Electric Field Strength (V/m or N/C)', color='#cccccc', fontsize=12)
    ax_wave.tick_params(colors='#bbbbbb')
    ax_wave.set_ylim(-1.15, 1.15)
    
    def scale_formatter(val, pos):
        scaled_val = val / scale_factor
        if scaled_val.is_integer():
            return f"{int(scaled_val)}"
        return f"{scaled_val:.3f}".rstrip('0').rstrip('.')

    ax_wave.xaxis.set_major_formatter(FuncFormatter(scale_formatter))

def update_display(wl_nm):
    global current_wl, wave_line, core_line
    current_wl = int(round(wl_nm))
    text_wl.set_val(str(current_wl))
    
    freq = wl_to_freq(current_wl)
    wavelength_m = current_wl * 1e-9
    
    ax_wave.clear()
    setup_axes(wavelength_m)
    
    x = np.linspace(0, 8 * wavelength_m, 1400)
    k = 2 * np.pi / wavelength_m
    E = np.sin(k * x)
    
    color = wavelength_to_rgb_cie(current_wl)
    
    wave_line, = ax_wave.plot(x, E, color=color, lw=5.0, label='Electromagnetic Wave', alpha=0.95)
    core_line, = ax_wave.plot(x, E, color='white', lw=1.5, alpha=0.5)
    
    ax_wave.legend(loc='upper right', labelcolor='white', frameon=True, facecolor='#1a1a1a')
    ax_wave.set_xlim(0, 8 * wavelength_m)
    
    energy = (H * freq) / 1.60217662e-19
    readable_freq = format_frequency(freq)
    
    ax_info.clear()
    ax_info.axis('off')
    info = f"Wavelength : {current_wl} nm\nFrequency  : {readable_freq}\nEnergy     : {energy:.6f} eV"
    ax_info.text(0.02, 0.85, info, color='#eeeeee', fontsize=11.5, family='monospace', va='top')

def submit_wl(text):
    global current_wl
    try:
        wl = int(float(text))
        if wl < 1:
            text_wl.set_val(str(current_wl))
        else:
            update_display(wl)
    except (ValueError, TypeError):
        text_wl.set_val(str(current_wl))

text_wl.on_submit(submit_wl)

def animate(frame):
    if wave_line is None or core_line is None:
        return
    wavelength_m = current_wl * 1e-9
    x = np.linspace(0, 8 * wavelength_m, 1400)
    k = 2 * np.pi / wavelength_m
    t = frame * 0.016
    E = np.sin(k * x - 2 * np.pi * t)
    
    wave_line.set_data(x, E)
    core_line.set_data(x, E)

update_display(380)
anim = FuncAnimation(fig, animate, interval=30, cache_frame_data=False)

plt.show()