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

// go/src/gui/utils/custom_widgets.go
// go/src/gui/utils/custom_widgets.go
package utils

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// SizedLabel is a custom label that allows text size control through scaling
type SizedLabel struct {
	widget.Label
	scale float32
}

// NewSizedLabel creates a new label with size scaling
func NewSizedLabel(text string, scale float32) *SizedLabel {
	label := &SizedLabel{
		scale: scale,
	}
	label.ExtendBaseWidget(label)
	label.SetText(text)
	return label
}

// MinSize returns the minimum size with scaling applied
func (l *SizedLabel) MinSize() fyne.Size {
	min := l.Label.MinSize()
	return fyne.NewSize(min.Width*l.scale, min.Height*l.scale)
}

// CreateLargeHeader creates a large header with custom sizing
func CreateLargeHeader(title, subtitle string) fyne.CanvasObject {
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subtitleLabel := widget.NewLabelWithStyle(subtitle, fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	// Use padding to create the appearance of larger text
	return container.NewVBox(
		container.NewPadded(titleLabel),
		subtitleLabel,
	)
}
