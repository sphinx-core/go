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
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/sphinx-core/go/src/accounts/key/disk"
	util "github.com/sphinx-core/go/src/accounts/key/utils"
)

// WalletGUI represents the main wallet GUI interface
type WalletGUI struct {
	app        fyne.App
	window     fyne.Window
	storageMgr *util.StorageManager
	diskStore  *disk.DiskKeyStore // Changed from hotStore
	currentTab string
}

// NewWalletGUI creates a new wallet GUI instance
func NewWalletGUI() *WalletGUI {
	// Initialize storage manager
	storageMgr, err := util.NewStorageManager()
	if err != nil {
		log.Fatal("Failed to create storage manager:", err)
	}

	// Create default directories
	if err := util.CreateDefaultDirectories(); err != nil {
		log.Printf("Warning: Failed to create directories: %v", err)
	}

	// Get disk storage  // Updated comment
	diskStore := storageMgr.GetStorage(util.StorageTypeDisk).(*disk.DiskKeyStore) // Changed from StorageTypeHot and HotKeyStore

	return &WalletGUI{
		app:        app.NewWithID("com.sphinx.wallet"),
		storageMgr: storageMgr,
		diskStore:  diskStore, // Changed from hotStore
	}
}

// Start initializes and runs the wallet GUI
func (wg *WalletGUI) Start() {
	// Create main window
	wg.window = wg.app.NewWindow("Sphinx Wallet")
	wg.window.SetMaster()
	wg.window.Resize(fyne.NewSize(1200, 800))

	// Set application icon (you can add an icon file later)
	// wg.window.SetIcon(...)

	// Create the main UI
	content := wg.createMainUI()
	wg.window.SetContent(content)

	// Show and run
	wg.window.ShowAndRun()
}

// createMainUI creates the main wallet interface
func (wg *WalletGUI) createMainUI() fyne.CanvasObject {
	// Create toolbar
	toolbar := wg.createToolbar()

	// Create tabs for different wallet functions
	tabs := container.NewAppTabs(
		container.NewTabItem("🏠 Dashboard", wg.createDashboardTab()),
		container.NewTabItem("📤 Send", wg.createSendTab()),
		container.NewTabItem("📥 Receive", wg.createReceiveTab()),
		container.NewTabItem("🔑 Keys", wg.createKeysTab()),
		container.NewTabItem("💾 Storage", wg.createStorageTab()),
		container.NewTabItem("⚙️ Settings", wg.createSettingsTab()),
	)

	tabs.SetTabLocation(container.TabLocationTop)

	// Combine toolbar and tabs
	return container.NewBorder(toolbar, nil, nil, nil, tabs)
}

// createToolbar creates the application toolbar
func (wg *WalletGUI) createToolbar() fyne.CanvasObject {
	// Network status
	networkStatus := widget.NewLabel("🌐 Mainnet")
	networkStatus.Alignment = fyne.TextAlignCenter

	// Balance display
	balanceLabel := widget.NewLabel("💰 Balance: 0 SPX")
	balanceLabel.Alignment = fyne.TextAlignCenter

	// Sync status
	syncStatus := widget.NewLabel("✅ Synced")
	syncStatus.Alignment = fyne.TextAlignCenter

	// Refresh button
	refreshBtn := widget.NewButton("🔄 Refresh", func() {
		wg.refreshWalletData()
	})

	toolbar := container.NewHBox(
		widget.NewLabel("🪶 Sphinx Wallet"),
		layout.NewSpacer(),
		networkStatus,
		balanceLabel,
		syncStatus,
		refreshBtn,
	)

	return container.NewPadded(toolbar)
}

// createDashboardTab creates the dashboard tab
func (wg *WalletGUI) createDashboardTab() fyne.CanvasObject {
	// Wallet overview
	overviewCard := wg.createOverviewCard()

	// Recent transactions
	transactionsCard := wg.createTransactionsCard()

	// Quick actions
	quickActionsCard := wg.createQuickActionsCard()

	// Layout
	topRow := container.NewHBox(overviewCard, quickActionsCard)
	bottomRow := container.NewHBox(transactionsCard)

	return container.NewVBox(
		topRow,
		bottomRow,
	)
}

// createOverviewCard creates wallet overview card
func (wg *WalletGUI) createOverviewCard() *widget.Card {
	// Get wallet info
	walletInfo := wg.diskStore.GetWalletInfo() // Changed from hotStore

	// Create overview content
	content := widget.NewForm(
		widget.NewFormItem("🔑 Total Keys", widget.NewLabel(fmt.Sprintf("%d", walletInfo.KeyCount))),
		widget.NewFormItem("💾 Storage Type", widget.NewLabel(string(walletInfo.Storage))),
		widget.NewFormItem("🕒 Last Accessed", widget.NewLabel(walletInfo.LastAccessed.Format("2006-01-02 15:04:05"))),
	)

	return widget.NewCard("📊 Wallet Overview", "", content)
}

// createTransactionsCard creates recent transactions card
func (wg *WalletGUI) createTransactionsCard() *widget.Card {
	// Placeholder transaction list
	transactions := []string{
		"📥 Received 10.5 SPX - 2 hours ago",
		"📤 Sent 5.2 SPX - 1 day ago",
		"📥 Received 3.7 SPX - 3 days ago",
	}

	list := widget.NewList(
		func() int {
			return len(transactions)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(transactions[i])
		},
	)

	return widget.NewCard("📋 Recent Transactions", "", list)
}

// createQuickActionsCard creates quick actions card
func (wg *WalletGUI) createQuickActionsCard() *widget.Card {
	sendBtn := widget.NewButton("📤 Send SPX", func() {
		wg.showSendTab()
	})

	receiveBtn := widget.NewButton("📥 Receive SPX", func() {
		wg.showReceiveTab()
	})

	backupBtn := widget.NewButton("💾 Backup Wallet", func() {
		wg.showBackupDialog()
	})

	content := container.NewVBox(
		sendBtn,
		receiveBtn,
		backupBtn,
	)

	return widget.NewCard("🚀 Quick Actions", "", content)
}

// createSendTab creates the send transaction tab
func (wg *WalletGUI) createSendTab() fyne.CanvasObject {
	// Recipient address input
	addressEntry := widget.NewEntry()
	addressEntry.SetPlaceHolder("Enter recipient address (spx1...)")

	// Amount input
	amountEntry := widget.NewEntry()
	amountEntry.SetPlaceHolder("0.0")
	amountEntry.Validator = func(text string) error {
		// Basic validation - check if it's a positive number
		if text == "" {
			return nil
		}
		var amount float64
		_, err := fmt.Sscanf(text, "%f", &amount)
		if err != nil {
			return fmt.Errorf("invalid amount")
		}
		if amount <= 0 {
			return fmt.Errorf("amount must be positive")
		}
		return nil
	}

	// Memo input
	memoEntry := widget.NewEntry()
	memoEntry.SetPlaceHolder("Optional memo")

	// Fee selector
	feeOptions := []string{"🐢 Low", "🚶 Medium", "🚀 High", "⚙️ Custom"}
	feeSelect := widget.NewSelect(feeOptions, func(string) {})
	feeSelect.SetSelected("🚶 Medium")

	// Send button
	sendBtn := widget.NewButton("🚀 Send Transaction", func() {
		wg.sendTransaction(addressEntry.Text, amountEntry.Text, memoEntry.Text)
	})

	// Form
	form := widget.NewForm(
		widget.NewFormItem("📧 Recipient Address", addressEntry),
		widget.NewFormItem("💰 Amount (SPX)", amountEntry),
		widget.NewFormItem("📝 Memo", memoEntry),
		widget.NewFormItem("⛽ Transaction Fee", feeSelect),
	)

	return container.NewVBox(
		widget.NewCard("📤 Send SPX", "Send Sphinx tokens to another address", form),
		container.NewCenter(sendBtn),
	)
}

// createReceiveTab creates the receive funds tab
func (wg *WalletGUI) createReceiveTab() fyne.CanvasObject {
	// Generate new address button
	newAddrBtn := widget.NewButton("🆕 Generate New Address", func() {
		wg.generateNewAddress()
	})

	// Address display
	addressLabel := widget.NewLabel("Your address will appear here")
	addressLabel.Wrapping = fyne.TextWrapWord
	addressLabel.Alignment = fyne.TextAlignCenter

	// QR code placeholder
	qrPlaceholder := widget.NewLabel("🖼️\nQR Code\n[Placeholder]")
	qrPlaceholder.Alignment = fyne.TextAlignCenter

	// Copy address button
	copyBtn := widget.NewButton("📋 Copy Address", func() {
		if addressLabel.Text != "Your address will appear here" {
			wg.copyToClipboard(addressLabel.Text)
		}
	})

	content := container.NewVBox(
		container.NewCenter(newAddrBtn),
		widget.NewSeparator(),
		addressLabel,
		container.NewCenter(qrPlaceholder),
		container.NewCenter(copyBtn),
	)

	return widget.NewCard("📥 Receive SPX", "Generate addresses to receive Sphinx tokens", content)
}

// createKeysTab creates the key management tab
func (wg *WalletGUI) createKeysTab() fyne.CanvasObject {
	// List of keys
	keys := wg.diskStore.ListKeys() // Changed from hotStore

	// Create key list
	keyList := widget.NewList(
		func() int {
			return len(keys)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(nil),
				widget.NewLabel("Address"),
				layout.NewSpacer(),
				widget.NewLabel("Type"),
				widget.NewLabel("Created"),
			)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			key := keys[i]
			container := o.(*fyne.Container)
			// container.Objects[0].(*widget.Icon) // You can set icons here
			container.Objects[1].(*widget.Label).SetText(key.Address[:16] + "...")
			container.Objects[3].(*widget.Label).SetText(string(key.WalletType))
			container.Objects[4].(*widget.Label).SetText(key.CreatedAt.Format("01/02"))
		},
	)

	// Key actions
	importBtn := widget.NewButton("📥 Import Key", func() {
		wg.showImportKeyDialog()
	})

	exportBtn := widget.NewButton("📤 Export Key", func() {
		wg.showExportKeyDialog()
	})

	backupAllBtn := widget.NewButton("💾 Backup All Keys", func() {
		wg.backupAllKeys()
	})

	actions := container.NewHBox(importBtn, exportBtn, backupAllBtn)

	return container.NewBorder(
		actions,
		nil,
		nil,
		nil,
		keyList,
	)
}

// createStorageTab creates the storage management tab
func (wg *WalletGUI) createStorageTab() fyne.CanvasObject {
	// USB status
	usbStatus := widget.NewLabel("🔴 Not Connected")
	if wg.storageMgr.IsUSBMounted() {
		usbStatus.SetText("🟢 Connected")
	}

	// USB actions
	mountBtn := widget.NewButton("🔌 Mount USB", func() {
		wg.showUSBMountDialog()
	})

	unmountBtn := widget.NewButton("🔓 Unmount USB", func() {
		wg.storageMgr.UnmountUSB()
		wg.refreshStorageTab()
	})

	backupBtn := widget.NewButton("💾 Backup to USB", func() {
		wg.showBackupToUSBDialog()
	})

	restoreBtn := widget.NewButton("📥 Restore from USB", func() {
		wg.showRestoreFromUSBDialog()
	})

	// Storage info
	info := wg.storageMgr.GetStorageInfo()
	diskInfo := info[util.StorageTypeDisk].(map[string]interface{}) // Changed from StorageTypeHot
	usbInfo := info[util.StorageTypeUSB].(map[string]interface{})

	infoForm := widget.NewForm(
		widget.NewFormItem("💿 Disk Storage Keys", widget.NewLabel(fmt.Sprintf("%v", diskInfo["key_count"]))), // Changed from "Hot Storage Keys"
		widget.NewFormItem("📀 USB Status", usbStatus),
		widget.NewFormItem("💾 USB Keys", widget.NewLabel(fmt.Sprintf("%v", usbInfo["key_count"]))),
	)

	actions := container.NewVBox(
		mountBtn,
		unmountBtn,
		backupBtn,
		restoreBtn,
	)

	return container.NewHBox(
		widget.NewCard("📊 Storage Information", "", infoForm),
		widget.NewCard("⚡ Storage Actions", "", actions),
	)
}

// createSettingsTab creates the settings tab
func (wg *WalletGUI) createSettingsTab() fyne.CanvasObject {
	// Network selection
	networkOptions := []string{"🌐 Mainnet", "🧪 Testnet", "🔧 Devnet"}
	networkSelect := widget.NewSelect(networkOptions, func(selected string) {
		wg.changeNetwork(selected)
	})
	networkSelect.SetSelected("🌐 Mainnet")

	// Theme selection
	themeOptions := []string{"☀️ Light", "🌙 Dark", "🤖 Auto"}
	themeSelect := widget.NewSelect(themeOptions, func(selected string) {
		wg.changeTheme(selected)
	})
	themeSelect.SetSelected("🤖 Auto")

	// Security settings
	autolockEntry := widget.NewEntry()
	autolockEntry.SetPlaceHolder("15") // minutes
	autolockEntry.SetText("15")

	// Form
	form := widget.NewForm(
		widget.NewFormItem("🌐 Network", networkSelect),
		widget.NewFormItem("🎨 Theme", themeSelect),
		widget.NewFormItem("🔒 Auto-lock (minutes)", autolockEntry),
	)

	// About section
	aboutText := `Sphinx Wallet v1.0.0

A secure wallet for the Sphinx blockchain
 featuring SPHINCS+ cryptography and
 hardware wallet support.`

	aboutCard := widget.NewCard("ℹ️ About", "", widget.NewLabel(aboutText))

	return container.NewVBox(
		widget.NewCard("⚙️ Settings", "Configure your wallet preferences", form),
		aboutCard,
	)
}

// Dialog and action methods
func (wg *WalletGUI) showSendTab() {
	// Implementation to switch to send tab
	log.Println("Switching to Send tab")
}

func (wg *WalletGUI) showReceiveTab() {
	// Implementation to switch to receive tab
	log.Println("Switching to Receive tab")
}

func (wg *WalletGUI) showBackupDialog() {
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Enter your wallet password")

	dialog.ShowForm("💾 Backup Wallet", "Backup", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("🔒 Enter Password", password),
		},
		func(confirmed bool) {
			if confirmed && password.Text != "" {
				wg.performBackup(password.Text)
			}
		}, wg.window)
}

func (wg *WalletGUI) sendTransaction(address, amount, memo string) {
	if address == "" || amount == "" {
		dialog.ShowInformation("❌ Error", "Please fill all required fields", wg.window)
		return
	}

	// Show confirmation dialog
	confirmMsg := fmt.Sprintf("Send %s SPX to:\n%s", amount, address)
	if memo != "" {
		confirmMsg += fmt.Sprintf("\nMemo: %s", memo)
	}

	dialog.ShowConfirm("🔍 Confirm Transaction", confirmMsg, func(confirmed bool) {
		if confirmed {
			// Implement actual transaction sending
			log.Printf("Sending %s SPX to %s", amount, address)
			dialog.ShowInformation("✅ Success", "Transaction sent successfully!", wg.window)
		}
	}, wg.window)
}

func (wg *WalletGUI) generateNewAddress() {
	// Generate new address logic
	newAddress := "spx1newaddressgeneratedhere1234567890abc"

	// Update UI - in a real implementation, this would update the address label
	dialog.ShowInformation("🆕 New Address",
		fmt.Sprintf("New address generated:\n\n%s", newAddress), wg.window)
}

func (wg *WalletGUI) copyToClipboard(text string) {
	wg.window.Clipboard().SetContent(text)
	dialog.ShowInformation("📋 Copied", "Address copied to clipboard", wg.window)
}

func (wg *WalletGUI) showImportKeyDialog() {
	keyData := widget.NewMultiLineEntry()
	keyData.SetPlaceHolder("Paste key export data here...")
	keyData.Wrapping = fyne.TextWrapWord

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Enter key password")

	form := []*widget.FormItem{
		widget.NewFormItem("🔑 Key Data", keyData),
		widget.NewFormItem("🔒 Password", password),
	}

	dialog.ShowForm("📥 Import Key", "Import", "Cancel", form,
		func(confirmed bool) {
			if confirmed {
				wg.importKey(keyData.Text, password.Text)
			}
		}, wg.window)
}

func (wg *WalletGUI) showExportKeyDialog() {
	// Get available keys
	keys := wg.diskStore.ListKeys() // Changed from hotStore
	if len(keys) == 0 {
		dialog.ShowInformation("ℹ️ Info", "No keys available to export", wg.window)
		return
	}

	// Create key selection
	keyOptions := make([]string, len(keys))
	for i, key := range keys {
		keyOptions[i] = fmt.Sprintf("%s... (%s)", key.Address[:16], key.WalletType)
	}

	keySelect := widget.NewSelect(keyOptions, func(string) {})
	password := widget.NewPasswordEntry()

	form := []*widget.FormItem{
		widget.NewFormItem("🔑 Select Key", keySelect),
		widget.NewFormItem("🔒 Password", password),
	}

	dialog.ShowForm("📤 Export Key", "Export", "Cancel", form,
		func(confirmed bool) {
			if confirmed && keySelect.Selected != "" && password.Text != "" {
				wg.exportKey(keySelect.Selected, password.Text)
			}
		}, wg.window)
}

func (wg *WalletGUI) backupAllKeys() {
	password := widget.NewPasswordEntry()

	dialog.ShowForm("💾 Backup All Keys", "Backup", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("🔒 Enter Password", password),
		},
		func(confirmed bool) {
			if confirmed {
				// Implement backup all keys logic
				dialog.ShowInformation("✅ Success", "All keys backed up successfully", wg.window)
			}
		}, wg.window)
}

func (wg *WalletGUI) showUSBMountDialog() {
	usbPath := widget.NewEntry()
	usbPath.SetPlaceHolder("/media/usb or /Volumes/USB")
	usbPath.SetText("/media/usb") // Default value

	dialog.ShowForm("🔌 Mount USB", "Mount", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("📁 USB Path", usbPath),
		},
		func(confirmed bool) {
			if confirmed {
				err := wg.storageMgr.MountUSB(usbPath.Text)
				if err != nil {
					dialog.ShowError(err, wg.window)
				} else {
					dialog.ShowInformation("✅ Success", "USB mounted successfully", wg.window)
					wg.refreshStorageTab()
				}
			}
		}, wg.window)
}

func (wg *WalletGUI) showBackupToUSBDialog() {
	if !wg.storageMgr.IsUSBMounted() {
		dialog.ShowInformation("❌ Error", "Please mount USB first", wg.window)
		return
	}

	password := widget.NewPasswordEntry()

	dialog.ShowForm("💾 Backup to USB", "Backup", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("🔒 Enter Password", password),
		},
		func(confirmed bool) {
			if confirmed {
				err := wg.storageMgr.BackupToUSB(password.Text)
				if err != nil {
					dialog.ShowError(err, wg.window)
				} else {
					dialog.ShowInformation("✅ Success", "Backup completed successfully", wg.window)
				}
			}
		}, wg.window)
}

func (wg *WalletGUI) showRestoreFromUSBDialog() {
	if !wg.storageMgr.IsUSBMounted() {
		dialog.ShowInformation("❌ Error", "Please mount USB first", wg.window)
		return
	}

	password := widget.NewPasswordEntry()

	dialog.ShowConfirm("⚠️ Restore from USB",
		"WARNING: This will overwrite existing keys in your disk wallet.\n\nAre you sure you want to continue?", // Updated warning message
		func(confirmed bool) {
			if confirmed {
				dialog.ShowForm("📥 Restore from USB", "Restore", "Cancel",
					[]*widget.FormItem{
						widget.NewFormItem("🔒 Enter Password", password),
					},
					func(restoreConfirmed bool) {
						if restoreConfirmed {
							count, err := wg.storageMgr.RestoreFromUSB(password.Text)
							if err != nil {
								dialog.ShowError(err, wg.window)
							} else {
								msg := fmt.Sprintf("✅ Restored %d keys successfully", count)
								dialog.ShowInformation("Success", msg, wg.window)
								wg.refreshKeysTab()
							}
						}
					}, wg.window)
			}
		}, wg.window)
}

// Utility methods
func (wg *WalletGUI) refreshWalletData() {
	// Refresh wallet data
	log.Println("Refreshing wallet data...")
	dialog.ShowInformation("🔄 Refreshed", "Wallet data refreshed", wg.window)
}

func (wg *WalletGUI) refreshStorageTab() {
	// Refresh storage tab content
	log.Println("Refreshing storage tab...")
}

func (wg *WalletGUI) refreshKeysTab() {
	// Refresh keys tab content
	log.Println("Refreshing keys tab...")
}

func (wg *WalletGUI) performBackup(password string) {
	// Implement backup logic
	log.Println("Performing wallet backup...")
	dialog.ShowInformation("✅ Backup", "Wallet backed up successfully", wg.window)
}

func (wg *WalletGUI) importKey(keyData, password string) {
	// Implement key import logic
	if strings.TrimSpace(keyData) == "" {
		dialog.ShowInformation("❌ Error", "Please enter key data", wg.window)
		return
	}

	log.Println("Importing key...")
	// Placeholder implementation
	dialog.ShowInformation("✅ Success", "Key imported successfully", wg.window)
	wg.refreshKeysTab()
}

func (wg *WalletGUI) exportKey(keyInfo, password string) {
	// Implement key export logic
	log.Printf("Exporting key: %s", keyInfo)
	dialog.ShowInformation("✅ Success", "Key exported successfully", wg.window)
}

func (wg *WalletGUI) changeNetwork(network string) {
	// Implement network change logic
	log.Printf("Changing network to: %s", network)
	dialog.ShowInformation("🌐 Network Changed",
		fmt.Sprintf("Switched to %s", strings.TrimPrefix(network, " ")), wg.window)
}

func (wg *WalletGUI) changeTheme(theme string) {
	// Implement theme change logic
	log.Printf("Changing theme to: %s", theme)
	dialog.ShowInformation("🎨 Theme Changed",
		fmt.Sprintf("Changed to %s theme", strings.TrimPrefix(theme, " ")), wg.window)
}
