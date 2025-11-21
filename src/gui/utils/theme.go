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

// SphinxTheme defines a custom theme for the Sphinx Wallet
type SphinxTheme struct {
	fyne.Theme
}

// NewSphinxTheme creates a new Sphinx wallet theme
func NewSphinxTheme() fyne.Theme {
	return &SphinxTheme{Theme: theme.DefaultTheme()}
}

// Color returns custom colors for the Sphinx theme
func (t *SphinxTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 59, G: 130, B: 246, A: 255} // Blue-500
	case theme.ColorNameButton:
		return color.NRGBA{R: 99, G: 102, B: 241, A: 255} // Indigo-500
	case theme.ColorNameFocus:
		return color.NRGBA{R: 139, G: 92, B: 246, A: 255} // Purple-500
	default:
		return t.Theme.Color(name, variant)
	}
}

// Font returns custom fonts for the Sphinx theme
func (t *SphinxTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.Theme.Font(style)
}

// Icon returns custom icons for the Sphinx theme
func (t *SphinxTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.Theme.Icon(name)
}

// Size returns custom sizes for the Sphinx theme
func (t *SphinxTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInlineIcon:
		return 20
	case theme.SizeNameText:
		return 14
	default:
		return t.Theme.Size(name)
	}
}
