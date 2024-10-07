package require Tk 8.6

namespace eval ::azure::theme {
    variable version 1.0
    variable colors
    array set colors {
        -fg             "#000000"
        -bg             "#ffffff"
        -disabledfg     "#737373"
        -selectfg       "#ffffff"
        -selectbg       "#007fff"
    }
}

proc ::azure::theme::init {} {
    variable colors

    ttk::style theme create azure -parent default -settings {
        ttk::style configure . \
            -background $colors(-bg) \
            -foreground $colors(-fg) \
            -troughcolor $colors(-bg) \
            -focuscolor $colors(-selectbg) \
            -selectbackground $colors(-selectbg) \
            -selectforeground $colors(-selectfg) \
            -insertcolor $colors(-fg) \
            -insertwidth 1 \
            -fieldbackground $colors(-bg) \
            -font TkDefaultFont \
            -borderwidth 1 \
            -relief flat

        ttk::style map . -foreground [list disabled $colors(-disabledfg)]

        ttk::style configure TButton \
            -anchor center -width -11 -padding {5 1} -relief flat
        ttk::style map TButton \
            -background [list pressed "#6dadf4" active "#8bbcf4"] \
            -relief [list {pressed !disabled} sunken]
    }
}

::azure::theme::init