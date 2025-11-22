// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/gui/utils/themes.go
package utils

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// ThemeManager manages application themes
type ThemeManager struct {
	currentTheme string
	isDarkMode   bool
}

// NewThemeManager creates a new theme manager
func NewThemeManager() *ThemeManager {
	return &ThemeManager{
		currentTheme: "auto",
		isDarkMode:   false,
	}
}

// SphinxTheme defines a custom theme for the Sphinx Wallet
type SphinxTheme struct {
	isDark bool
}

// NewSphinxLightTheme creates light theme
func NewSphinxLightTheme() fyne.Theme {
	return &SphinxTheme{isDark: false}
}

// NewSphinxDarkTheme creates dark theme
func NewSphinxDarkTheme() fyne.Theme {
	return &SphinxTheme{isDark: true}
}

// Color returns theme colors
func (t *SphinxTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	if t.isDark {
		return t.darkColor(name)
	}
	return t.lightColor(name)
}

// lightColor returns light theme colors
func (t *SphinxTheme) lightColor(name fyne.ThemeColorName) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 59, G: 130, B: 246, A: 255} // Blue-500
	case theme.ColorNameButton:
		return color.NRGBA{R: 99, G: 102, B: 241, A: 255} // Indigo-500
	case theme.ColorNameFocus:
		return color.NRGBA{R: 139, G: 92, B: 246, A: 255} // Purple-500
	case theme.ColorNameBackground:
		return color.NRGBA{R: 249, G: 250, B: 251, A: 255} // Gray-50
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 255, G: 255, B: 255, A: 255} // White
	case theme.ColorNameForeground:
		return color.NRGBA{R: 17, G: 24, B: 39, A: 255} // Gray-900
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 156, G: 163, B: 175, A: 255} // Gray-400
	default:
		return theme.DefaultTheme().Color(name, theme.VariantLight)
	}
}

// darkColor returns dark theme colors
func (t *SphinxTheme) darkColor(name fyne.ThemeColorName) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 96, G: 165, B: 250, A: 255} // Blue-300
	case theme.ColorNameButton:
		return color.NRGBA{R: 129, G: 140, B: 248, A: 255} // Indigo-400
	case theme.ColorNameFocus:
		return color.NRGBA{R: 167, G: 139, B: 250, A: 255} // Purple-400
	case theme.ColorNameBackground:
		return color.NRGBA{R: 17, G: 24, B: 39, A: 255} // Gray-900
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 31, G: 41, B: 55, A: 255} // Gray-800
	case theme.ColorNameForeground:
		return color.NRGBA{R: 249, G: 250, B: 251, A: 255} // Gray-50
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 107, G: 114, B: 128, A: 255} // Gray-500
	default:
		return theme.DarkTheme().Color(name, theme.VariantDark)
	}
}

// Font returns custom fonts
func (t *SphinxTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon returns custom icons
func (t *SphinxTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns custom sizes
func (t *SphinxTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 12
	case theme.SizeNameInlineIcon:
		return 20
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 18
	case theme.SizeNameSubHeadingText:
		return 16
	default:
		return theme.DefaultTheme().Size(name)
	}
}
