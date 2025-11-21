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

// go/src/gui/utils/component.go
// go/src/gui/utils/components.go
package utils

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// CreateHeader creates a standardized header component
func CreateHeader(title string, subtitle string) fyne.CanvasObject {
	titleLabel := widget.NewLabel(title)
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}
	titleLabel.Alignment = fyne.TextAlignCenter

	subtitleLabel := widget.NewLabel(subtitle)
	subtitleLabel.TextStyle = fyne.TextStyle{Italic: true}
	subtitleLabel.Alignment = fyne.TextAlignCenter

	return container.NewVBox(
		titleLabel,
		subtitleLabel,
	)
}

// CreateBalanceDisplay creates a balance display component
func CreateBalanceDisplay(balance string, currency string) fyne.CanvasObject {
	// For larger text, we can use a custom approach
	balanceLabel := widget.NewLabel(balance)
	balanceLabel.TextStyle = fyne.TextStyle{Bold: true}
	balanceLabel.Alignment = fyne.TextAlignCenter

	// To make text appear larger, we can use padding and layout
	balanceContainer := container.NewPadded(balanceLabel)

	currencyLabel := widget.NewLabel(currency)
	currencyLabel.Alignment = fyne.TextAlignCenter

	return container.NewVBox(
		balanceContainer,
		currencyLabel,
	)
}

// CreateLargeText creates a label with larger appearance
func CreateLargeText(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.TextStyle = fyne.TextStyle{Bold: true}
	// Use padding to make it appear larger
	return label
}

// CreateActionButton creates a styled action button
func CreateActionButton(text string, action func()) *widget.Button {
	button := widget.NewButton(text, action)
	// You can customize button appearance here if needed
	return button
}

// CreateFormSection creates a form section with title
func CreateFormSection(title string, items ...fyne.CanvasObject) fyne.CanvasObject {
	titleLabel := widget.NewLabel(title)
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}

	content := container.NewVBox(items...)

	return container.NewVBox(
		titleLabel,
		content,
	)
}

// CreateStatusIndicator creates a status indicator component
func CreateStatusIndicator(status string, isActive bool) fyne.CanvasObject {
	var icon string
	if isActive {
		icon = "🟢"
	} else {
		icon = "🔴"
	}

	statusLabel := widget.NewLabel(status)
	iconLabel := widget.NewLabel(icon)

	return container.NewHBox(
		iconLabel,
		statusLabel,
	)
}

// CreateCard creates a styled card component
func CreateCard(title string, content fyne.CanvasObject) *widget.Card {
	return widget.NewCard(title, "", content)
}

// CreateSpacer creates a flexible spacer
func CreateSpacer() fyne.CanvasObject {
	return layout.NewSpacer()
}

// CreateSeparator creates a visual separator
func CreateSeparator() fyne.CanvasObject {
	return widget.NewSeparator()
}

// CreateProgressBar creates a progress bar with label
func CreateProgressBar(labelText string) *widget.ProgressBar {
	return widget.NewProgressBar()
}

// CreateToolbar creates a simple toolbar
func CreateToolbar(items ...fyne.CanvasObject) fyne.CanvasObject {
	return container.NewHBox(items...)
}
