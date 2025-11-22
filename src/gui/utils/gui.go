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

// go/src/gui/utils/gui.go
package utils

import (
	"fmt"
	"log"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/sphinx-core/go/src/accounts/key"
	util "github.com/sphinx-core/go/src/accounts/key/utils"
)

// RunGUI starts the wallet GUI application
func RunGUI() {
	// Initialize storage through the keystore interface
	storageMgr, err := util.NewStorageManager()
	if err != nil {
		log.Fatal("Failed to create storage manager:", err)
	}

	// Register the storage manager with the keystore package
	key.SetStorageManager(storageMgr)

	if err := util.CreateDefaultDirectories(); err != nil {
		log.Printf("Warning: Failed to create directories: %v", err)
	}

	// Get disk store through keystore interface instead of direct import
	diskStore := key.GetDiskStorage()
	if diskStore == nil {
		log.Fatal("Failed to get disk storage")
	}

	// Create app and window
	myApp := app.NewWithID("com.sphinx.wallet")
	window := myApp.NewWindow("Sphinx Wallet")
	window.SetMaster()
	window.Resize(fyne.NewSize(1400, 900))
	window.CenterOnScreen()

	// Theme state
	isDarkMode := false
	themeManager := NewThemeManager()

	// Apply theme function
	applyTheme := func(dark bool) {
		if dark {
			myApp.Settings().SetTheme(NewSphinxDarkTheme())
		} else {
			myApp.Settings().SetTheme(NewSphinxLightTheme())
		}
		isDarkMode = dark
		themeManager.isDarkMode = dark
	}

	// Apply initial theme
	applyTheme(false)

	// Helper functions using the component utilities
	createInfoRow := func(label, value string) fyne.CanvasObject {
		return container.NewHBox(
			CreateStyledLabel(label, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			CreateSpacer(),
			widget.NewLabel(value),
		)
	}

	createStorageInfoRow := func(label, value string) fyne.CanvasObject {
		return container.NewPadded(container.NewHBox(
			CreateStyledLabel(label, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			CreateSpacer(),
			widget.NewLabel(value),
		))
	}

	// Create toolbar using component utilities
	toolbar := func() fyne.CanvasObject {
		title := CreateLargeHeader("🪶 Sphinx Wallet", "Secure SPX Wallet")

		networkStatus := container.NewHBox(
			widget.NewLabel("🌐"),
			CreateStyledLabel("Mainnet", fyne.TextAlignLeading, fyne.TextStyle{}),
		)
		networkStatusBox := container.NewVBox(
			CreateSubHeading("Network"),
			networkStatus,
		)

		balanceLabel := container.NewHBox(
			widget.NewLabel("💰"),
			CreateStyledLabel("0 SPX", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		)
		balanceBox := container.NewVBox(
			CreateSubHeading("Balance"),
			balanceLabel,
		)

		syncStatus := container.NewHBox(
			widget.NewLabel("✅"),
			CreateStatusIndicator("Synced", true),
		)
		syncBox := container.NewVBox(
			CreateSubHeading("Status"),
			syncStatus,
		)

		themeToggle := widget.NewCheck("", func(checked bool) {
			applyTheme(checked)
		})
		themeToggle.SetChecked(isDarkMode)
		themeBox := container.NewHBox(themeToggle, CreateSubHeading("🌙 Dark Mode"))

		refreshBtn := CreateActionButton("🔄 Refresh", func() {
			log.Println("Refreshing wallet data...")
			dialog.ShowInformation("🔄 Refreshed", "Wallet data refreshed", window)
		})

		toolbarContent := CreateToolbar(
			title,
			CreateSpacer(),
			networkStatusBox,
			balanceBox,
			syncBox,
			CreateSpacer(),
			themeBox,
			refreshBtn,
		)

		return container.NewPadded(container.NewBorder(nil, nil, nil, nil, toolbarContent))
	}

	// Create tabs
	createTabs := func() *container.AppTabs {
		// Dashboard Tab
		dashboardTab := func() fyne.CanvasObject {
			// Overview Card using component utilities
			walletInfo := diskStore.GetWalletInfo()
			overviewContent := container.NewVBox(
				createInfoRow("🔑 Total Keys", fmt.Sprintf("%d", walletInfo.KeyCount)),
				createInfoRow("💾 Storage Type", string(walletInfo.Storage)),
				createInfoRow("🕒 Last Accessed", walletInfo.LastAccessed.Format("2006-01-02 15:04:05")),
				createInfoRow("📊 Wallet Version", "v1.0.0"),
			)
			overviewCard := CreateCard("📊 Wallet Overview", overviewContent)

			// Transactions Card
			transactions := []struct {
				icon    string
				amount  string
				address string
				time    string
				status  string
			}{
				{"📥", "+10.5 SPX", "spx1abc...def", "2 hours ago", "Confirmed"},
				{"📤", "-5.2 SPX", "spx1xyz...uvw", "1 day ago", "Confirmed"},
				{"📥", "+3.7 SPX", "spx1mno...pqr", "3 days ago", "Confirmed"},
			}

			transactionList := container.NewVBox()
			for _, tx := range transactions {
				transaction := container.NewHBox(
					widget.NewLabel(tx.icon),
					container.NewVBox(
						CreateStyledLabel(tx.amount, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
						CreateStyledLabel(tx.address, fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
					),
					CreateSpacer(),
					container.NewVBox(
						widget.NewLabel(tx.time),
						CreateStyledLabel(tx.status, fyne.TextAlignTrailing, fyne.TextStyle{Italic: true}),
					),
				)
				transactionList.Add(transaction)
				transactionList.Add(CreateSeparator())
			}
			transactionsCard := CreateCard("📋 Recent Transactions", container.NewScroll(transactionList))

			// Quick Actions Card using component utilities
			sendBtn := CreateHoverButton("📤 Send SPX", func() {
				log.Println("Switching to Send tab")
			})
			sendBtn.Importance = widget.HighImportance

			receiveBtn := CreateHoverButton("📥 Receive SPX", func() {
				log.Println("Switching to Receive tab")
			})
			receiveBtn.Importance = widget.HighImportance

			backupBtn := CreateHoverButton("💾 Backup Wallet", func() {
				password := widget.NewPasswordEntry()
				dialog.ShowForm("💾 Backup Wallet", "Backup", "Cancel",
					[]*widget.FormItem{{Text: "🔒 Enter Password", Widget: password}},
					func(confirmed bool) {
						if confirmed && password.Text != "" {
							log.Println("Performing wallet backup...")
							dialog.ShowInformation("✅ Backup", "Wallet backed up successfully", window)
						}
					}, window)
			})
			backupBtn.Importance = widget.MediumImportance

			quickActionsCard := CreateCard("🚀 Quick Actions",
				container.NewGridWithColumns(1, sendBtn, receiveBtn, backupBtn))

			grid := container.NewAdaptiveGrid(2,
				container.NewVBox(overviewCard, quickActionsCard),
				transactionsCard,
			)

			return container.NewPadded(container.NewScroll(grid))
		}

		// Send Tab using component utilities
		sendTab := func() fyne.CanvasObject {
			addressEntry := widget.NewEntry()
			addressEntry.SetPlaceHolder("Enter recipient address (spx1...)")

			amountEntry := widget.NewEntry()
			amountEntry.SetPlaceHolder("0.0")

			memoEntry := widget.NewEntry()
			memoEntry.SetPlaceHolder("Optional memo")

			feeSelect := widget.NewSelect([]string{"🐢 Low", "🚶 Medium", "🚀 High", "⚙️ Custom"}, func(string) {})
			feeSelect.SetSelected("🚶 Medium")

			sendBtn := CreateActionButton("🚀 Send Transaction", func() {
				if addressEntry.Text == "" || amountEntry.Text == "" {
					dialog.ShowInformation("❌ Error", "Please fill all required fields", window)
					return
				}
				confirmMsg := fmt.Sprintf("Send %s SPX to:\n%s", amountEntry.Text, addressEntry.Text)
				if memoEntry.Text != "" {
					confirmMsg += fmt.Sprintf("\nMemo: %s", memoEntry.Text)
				}
				dialog.ShowConfirm("🔍 Confirm Transaction", confirmMsg, func(confirmed bool) {
					if confirmed {
						log.Printf("Sending %s SPX to %s", amountEntry.Text, addressEntry.Text)
						dialog.ShowInformation("✅ Success", "Transaction sent successfully!", window)
					}
				}, window)
			})
			sendBtn.Importance = widget.HighImportance

			form := CreateFormSection("📤 Send SPX",
				&widget.Form{
					Items: []*widget.FormItem{
						{Text: "📧 Recipient Address", Widget: addressEntry},
						{Text: "💰 Amount (SPX)", Widget: amountEntry},
						{Text: "📝 Memo", Widget: memoEntry},
						{Text: "⛽ Transaction Fee", Widget: feeSelect},
					},
				},
			)

			return container.NewVBox(
				form,
				container.NewCenter(sendBtn),
			)
		}

		// Receive Tab using component utilities
		receiveTab := func() fyne.CanvasObject {
			addressLabel := CreateLargeText("Your address will appear here")
			addressLabel.Wrapping = fyne.TextWrapWord
			addressLabel.Alignment = fyne.TextAlignCenter

			newAddrBtn := CreateActionButton("🆕 Generate New Address", func() {
				newAddress := "spx1newaddressgeneratedhere1234567890abc"
				dialog.ShowInformation("🆕 New Address",
					fmt.Sprintf("New address generated:\n\n%s", newAddress), window)
			})
			newAddrBtn.Importance = widget.HighImportance

			qrPlaceholder := CreateLargeText("🖼️\nQR Code\n[Placeholder]")
			qrPlaceholder.Alignment = fyne.TextAlignCenter

			copyBtn := CreateActionButton("📋 Copy Address", func() {
				window.Clipboard().SetContent(addressLabel.Text)
				dialog.ShowInformation("📋 Copied", "Address copied to clipboard", window)
			})

			content := container.NewVBox(
				container.NewCenter(newAddrBtn),
				CreateSeparator(),
				addressLabel,
				container.NewCenter(qrPlaceholder),
				container.NewCenter(copyBtn),
			)

			return CreateCard("📥 Receive SPX", content)
		}

		// Keys Tab using component utilities
		keysTab := func() fyne.CanvasObject {
			keys := diskStore.ListKeys()

			importBtn := CreateActionButton("📥 Import Key", func() {
				keyData := widget.NewMultiLineEntry()
				keyData.SetPlaceHolder("Paste key export data here...")
				password := widget.NewPasswordEntry()
				dialog.ShowForm("📥 Import Key", "Import", "Cancel",
					[]*widget.FormItem{
						{Text: "🔑 Key Data", Widget: keyData},
						{Text: "🔒 Password", Widget: password},
					},
					func(confirmed bool) {
						if confirmed {
							dialog.ShowInformation("✅ Success", "Key imported successfully", window)
						}
					}, window)
			})

			exportBtn := CreateActionButton("📤 Export Key", func() {
				if len(keys) == 0 {
					dialog.ShowInformation("ℹ️ Info", "No keys available to export", window)
					return
				}
				keyOptions := make([]string, len(keys))
				for i, key := range keys {
					keyOptions[i] = fmt.Sprintf("%s... (%s)", key.Address[:16], key.WalletType)
				}
				keySelect := widget.NewSelect(keyOptions, func(string) {})
				password := widget.NewPasswordEntry()
				dialog.ShowForm("📤 Export Key", "Export", "Cancel",
					[]*widget.FormItem{
						{Text: "🔑 Select Key", Widget: keySelect},
						{Text: "🔒 Password", Widget: password},
					},
					func(confirmed bool) {
						if confirmed && keySelect.Selected != "" {
							dialog.ShowInformation("✅ Success", "Key exported successfully", window)
						}
					}, window)
			})

			backupAllBtn := CreateActionButton("💾 Backup All Keys", func() {
				password := widget.NewPasswordEntry()
				dialog.ShowForm("💾 Backup All Keys", "Backup", "Cancel",
					[]*widget.FormItem{{Text: "🔒 Enter Password", Widget: password}},
					func(confirmed bool) {
						if confirmed {
							dialog.ShowInformation("✅ Success", "All keys backed up successfully", window)
						}
					}, window)
			})

			actions := CreateToolbar(
				CreateSpacer(),
				importBtn,
				CreateSpacer(),
				exportBtn,
				CreateSpacer(),
				backupAllBtn,
				CreateSpacer(),
			)

			keyList := widget.NewList(
				func() int { return len(keys) },
				func() fyne.CanvasObject {
					return container.NewHBox(
						container.NewHBox(
							widget.NewLabel("🔑"),
							container.NewVBox(
								CreateSubHeading("Address"),
								CreateSubHeading("Type"),
							),
						),
						CreateSpacer(),
						container.NewVBox(
							CreateSubHeading("Created"),
							CreateSubHeading("Status"),
						),
					)
				},
				func(i int, o fyne.CanvasObject) {
					key := keys[i]
					container := o.(*fyne.Container)
					leftSection := container.Objects[0].(*fyne.Container)
					rightSection := container.Objects[2].(*fyne.Container)

					addressLabel := leftSection.Objects[1].(*fyne.Container).Objects[0].(*widget.Label)
					typeLabel := leftSection.Objects[1].(*fyne.Container).Objects[1].(*widget.Label)

					addressLabel.SetText(key.Address[:16] + "...")
					typeLabel.SetText(string(key.WalletType))
					typeLabel.TextStyle = fyne.TextStyle{Italic: true}

					dateLabel := rightSection.Objects[0].(*widget.Label)
					statusLabel := rightSection.Objects[1].(*widget.Label)

					dateLabel.SetText(key.CreatedAt.Format("01/02/2006"))
					dateLabel.Alignment = fyne.TextAlignTrailing
					statusLabel.SetText("🟢 Active")
					statusLabel.Alignment = fyne.TextAlignTrailing
				},
			)

			return container.NewBorder(
				container.NewVBox(
					CreateHeading("🔑 Key Management"),
					CreateSeparator(),
					actions,
					CreateSeparator(),
				),
				nil, nil, nil,
				container.NewPadded(keyList),
			)
		}

		// Storage Tab using component utilities
		storageTab := func() fyne.CanvasObject {
			storageManager := key.GetStorageManager()
			info := storageManager.GetStorageInfo()

			diskInfo := info["disk"].(map[string]interface{})
			usbInfo := info["usb"].(map[string]interface{})

			usbStatus := "🔴 Not Connected"
			if storageManager.IsUSBMounted() {
				usbStatus = "🟢 Connected"
			}

			infoContent := container.NewVBox(
				createStorageInfoRow("💿 Disk Storage", fmt.Sprintf("%v keys", diskInfo["key_count"])),
				createStorageInfoRow("📀 USB Status", usbStatus),
				createStorageInfoRow("💾 USB Storage", fmt.Sprintf("%v keys", usbInfo["key_count"])),
				createStorageInfoRow("📊 Total Capacity", "500 GB"),
				createStorageInfoRow("💽 Free Space", "350 GB"),
			)
			infoCard := CreateCard("📊 Storage Information", infoContent)

			mountBtn := CreateActionButton("🔌 Mount USB", func() {
				usbPath := widget.NewEntry()
				usbPath.SetText("/media/usb")
				dialog.ShowForm("🔌 Mount USB", "Mount", "Cancel",
					[]*widget.FormItem{{Text: "📁 USB Path", Widget: usbPath}},
					func(confirmed bool) {
						if confirmed {
							err := storageManager.MountUSB(usbPath.Text)
							if err != nil {
								dialog.ShowError(err, window)
							} else {
								dialog.ShowInformation("✅ Success", "USB mounted successfully", window)
							}
						}
					}, window)
			})

			unmountBtn := CreateActionButton("🔓 Unmount USB", func() {
				storageManager.UnmountUSB()
				dialog.ShowInformation("ℹ️ Info", "USB unmounted", window)
			})

			backupBtn := CreateActionButton("💾 Backup to USB", func() {
				if !storageManager.IsUSBMounted() {
					dialog.ShowInformation("❌ Error", "Please mount USB first", window)
					return
				}
				password := widget.NewPasswordEntry()
				dialog.ShowForm("💾 Backup to USB", "Backup", "Cancel",
					[]*widget.FormItem{{Text: "🔒 Enter Password", Widget: password}},
					func(confirmed bool) {
						if confirmed {
							err := storageManager.BackupToUSB(password.Text)
							if err != nil {
								dialog.ShowError(err, window)
							} else {
								dialog.ShowInformation("✅ Success", "Backup completed successfully", window)
							}
						}
					}, window)
			})

			restoreBtn := CreateActionButton("📥 Restore from USB", func() {
				if !storageManager.IsUSBMounted() {
					dialog.ShowInformation("❌ Error", "Please mount USB first", window)
					return
				}
				dialog.ShowConfirm("⚠️ Restore from USB",
					"WARNING: This will overwrite existing keys in your disk wallet.\n\nAre you sure you want to continue?",
					func(confirmed bool) {
						if confirmed {
							password := widget.NewPasswordEntry()
							dialog.ShowForm("📥 Restore from USB", "Restore", "Cancel",
								[]*widget.FormItem{{Text: "🔒 Enter Password", Widget: password}},
								func(restoreConfirmed bool) {
									if restoreConfirmed {
										count, err := storageManager.RestoreFromUSB(password.Text)
										if err != nil {
											dialog.ShowError(err, window)
										} else {
											dialog.ShowInformation("Success", fmt.Sprintf("✅ Restored %d keys successfully", count), window)
										}
									}
								}, window)
						}
					}, window)
			})

			actionsCard := CreateCard("⚡ Storage Actions",
				container.NewGridWithColumns(1, mountBtn, unmountBtn, backupBtn, restoreBtn))

			grid := container.NewAdaptiveGrid(2, infoCard, actionsCard)
			return container.NewPadded(container.NewScroll(grid))
		}

		// Settings Tab using component utilities
		settingsTab := func() fyne.CanvasObject {
			themeSelect := widget.NewRadioGroup([]string{"☀️ Light", "🌙 Dark", "🤖 Auto"}, func(selected string) {
				switch selected {
				case "☀️ Light":
					applyTheme(false)
				case "🌙 Dark":
					applyTheme(true)
				case "🤖 Auto":
					applyTheme(false)
				}
			})
			themeSelect.Horizontal = true
			themeSelect.SetSelected("🤖 Auto")
			themeSection := CreateCard("🎨 Theme Settings",
				container.NewVBox(
					CreateHeading("Theme Mode"),
					themeSelect,
				))

			networkSelect := widget.NewSelect([]string{"🌐 Mainnet", "🧪 Testnet", "🔧 Devnet"}, func(selected string) {
				dialog.ShowInformation("🌐 Network Changed", fmt.Sprintf("Switched to %s", strings.TrimPrefix(selected, " ")), window)
			})
			networkSelect.SetSelected("🌐 Mainnet")
			networkSection := CreateCard("🌐 Network Settings",
				container.NewVBox(
					CreateHeading("Network"),
					networkSelect,
				))

			autolockEntry := widget.NewEntry()
			autolockEntry.SetText("15")
			securitySection := CreateCard("🔒 Security Settings",
				container.NewVBox(
					CreateHeading("Auto-lock (minutes)"),
					autolockEntry,
				))

			aboutText := `Sphinx Wallet v1.0.0

A secure wallet for the Sphinx blockchain
featuring SPHINCS+ cryptography and
hardware wallet support.

© 2024 Sphinx Core Team`
			aboutLabel := CreateStyledLabel(aboutText, fyne.TextAlignLeading, fyne.TextStyle{})
			aboutLabel.Wrapping = fyne.TextWrapWord
			aboutSection := CreateCard("ℹ️ About", aboutLabel)

			content := container.NewVBox(
				themeSection,
				CreateSeparator(),
				networkSection,
				CreateSeparator(),
				securitySection,
				CreateSeparator(),
				aboutSection,
			)

			return container.NewPadded(container.NewScroll(content))
		}

		// Create tabs container
		tabs := container.NewAppTabs(
			container.NewTabItem("🏠 Dashboard", dashboardTab()),
			container.NewTabItem("📤 Send", sendTab()),
			container.NewTabItem("📥 Receive", receiveTab()),
			container.NewTabItem("🔑 Keys", keysTab()),
			container.NewTabItem("💾 Storage", storageTab()),
			container.NewTabItem("⚙️ Settings", settingsTab()),
		)
		tabs.SetTabLocation(container.TabLocationTop)
		return tabs
	}

	// Set main content
	mainContent := container.NewBorder(toolbar(), nil, nil, nil, createTabs())
	window.SetContent(mainContent)

	// Show and run
	window.ShowAndRun()
}
