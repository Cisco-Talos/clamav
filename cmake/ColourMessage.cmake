# From https://stackoverflow.com/questions/18968979/how-to-get-colorized-output-with-cmake

string(ASCII 27 Esc)
set(e "${Esc}[m")     # Colour Reset
set(o "${Esc}[1m")    # Colour Bold
set(r "${Esc}[31m")   # Red
set(g "${Esc}[32m")   # Green
set(y "${Esc}[33m")   # Yellow
set(b "${Esc}[34m")   # Blue
set(m "${Esc}[35m")   # Magenta
set(c "${Esc}[36m")   # Cyan
set(w "${Esc}[37m")   # White
set(R "${Esc}[1;31m") # Bold Red
set(G "${Esc}[1;32m") # Bold Green
set(Y "${Esc}[1;33m") # Bold Yellow
set(B "${Esc}[1;34m") # Bold Blue
set(M "${Esc}[1;35m") # Bold Magenta
set(C "${Esc}[1;36m") # Bold Cyan
set(W "${Esc}[1;37m") # Bold White
set(_ "")             # No-op, for alignment purposes
