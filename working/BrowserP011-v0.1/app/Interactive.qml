// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Window
import QtWebEngine

Window {
    id: window
    width: 800
    height: 480
    flags: Qt.FramelessWindowHint
    color: "#080f17"
    visible: true
    title: "P011 浏览器"
    Component.onCompleted: interactive.recordStage("window_created")
    function visitAddress() {
        const target = interactive.addressFor(address.text)
        if (target.toString().length === 0) {
            notice.text = "请输入有效网页地址，仅支持 HTTP / HTTPS"
            return
        }
        notice.text = ""
        keyboard.visible = false
        browser.forceActiveFocus()
        browser.url = target
    }
    WebEngineProfile {
        id: privateProfile
        offTheRecord: true
        httpCacheType: WebEngineProfile.MemoryHttpCache
        persistentCookiesPolicy: WebEngineProfile.NoPersistentCookies
        persistentPermissionsPolicy: WebEngineProfile.StoreInMemory
        onDownloadRequested: function(download) { download.cancel(); interactive.recordStage("download_denied") }
    }
    Item {
        id: content
        x: 0
        y: 106
        width: 800
        height: 268
        clip: true
        Rectangle {
            id: toolbar
            width: parent.width
            height: 44
            color: "#162b3b"
            Row {
                x: 4
                y: 2
                spacing: 4
                BrowserButton { width: 48; label: "后退"; enabled: browser.canGoBack; onClicked: browser.goBack() }
                BrowserButton { width: 48; label: "前进"; enabled: browser.canGoForward; onClicked: browser.goForward() }
                BrowserButton { width: 60; label: "刷新"; onClicked: browser.reload() }
                BrowserButton { width: 60; label: "主页"; onClicked: { keyboard.visible = false; browser.url = interactive.startupUrl } }
                Rectangle {
                    width: toolbar.width - 420
                    height: 40
                    color: "#f1f6f9"
                    radius: 4
                    clip: true
                    TextInput {
                        id: address
                        anchors.fill: parent
                        anchors.margins: 6
                        verticalAlignment: TextInput.AlignVCenter
                        color: "#112736"
                        font.pixelSize: 20
                        text: "https://www.baidu.com/"
                        maximumLength: 2048
                        selectByMouse: true
                        inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoPredictiveText
                        onAccepted: window.visitAddress()
                        onActiveFocusChanged: if (activeFocus) { selectAll(); keyboard.visible = true }
                    }
                }
                BrowserButton { width: 52; label: "访问"; onClicked: window.visitAddress() }
                BrowserButton { width: 60; label: "键盘"; onClicked: keyboard.visible = !keyboard.visible }
                BrowserButton { width: 56; label: "退出"; onClicked: { interactive.recordStage("user_exit"); Qt.quit() } }
            }
        }
        WebEngineView {
            id: browser
            x: 0
            y: toolbar.height
            width: parent.width
            height: parent.height - toolbar.height - (keyboard.visible ? keyboard.height : 0)
            profile: privateProfile
            url: interactive.startupUrl
            backgroundColor: "#f1f6f9"
            settings.javascriptCanOpenWindows: false
            settings.javascriptCanAccessClipboard: false
            settings.javascriptCanPaste: false
            settings.localContentCanAccessRemoteUrls: false
            settings.localContentCanAccessFileUrls: false
            settings.pluginsEnabled: false
            settings.fullScreenSupportEnabled: false
            settings.screenCaptureEnabled: false
            settings.allowRunningInsecureContent: false
            settings.allowGeolocationOnInsecureOrigins: false
            settings.allowWindowActivationFromJavaScript: false
            settings.hyperlinkAuditingEnabled: false
            settings.navigateOnDropEnabled: false
            settings.unknownUrlSchemePolicy: WebEngineSettings.DisallowUnknownUrlSchemes
            onUrlChanged: if (!address.activeFocus) address.text = url.toString()
            onNavigationRequested: function(request) {
                if (!interactive.allowNavigation(request.url)) {
                    request.reject()
                    notice.text = "此地址不受支持"
                    interactive.recordStage("navigation_denied")
                }
            }
            onCertificateError: function(error) { error.rejectCertificate(); notice.text = "网站证书验证失败"; interactive.recordStage("certificate_denied") }
            onPermissionRequested: function(permission) { permission.deny(); interactive.recordStage("permission_denied") }
            onNewWindowRequested: function(request) {
                if (request.userInitiated && interactive.allowNavigation(request.requestedUrl)) {
                    keyboard.visible = false
                    browser.url = request.requestedUrl
                } else interactive.recordStage("popup_denied")
            }
            onFileDialogRequested: function(request) { request.accepted = true; request.dialogReject(); interactive.recordStage("file_dialog_denied") }
            onJavaScriptDialogRequested: function(request) { request.accepted = true; request.dialogReject(); interactive.recordStage("dialog_denied") }
            onAuthenticationDialogRequested: function(request) { request.accepted = true; request.dialogReject(); interactive.recordStage("dialog_denied") }
            onRegisterProtocolHandlerRequested: function(request) { request.reject(); interactive.recordStage("protocol_handler_denied") }
            onContextMenuRequested: function(request) { request.accepted = true }
            onJavaScriptConsoleMessage: function(level, message, lineNumber, sourceID) {}
            onLoadingChanged: function(info) {
                if (info.status === WebEngineView.LoadStartedStatus) {
                    notice.text = "正在加载…"
                    interactive.recordStage("load_started")
                } else if (info.status === WebEngineView.LoadSucceededStatus) {
                    notice.text = ""
                    interactive.recordStage("load_succeeded")
                } else if (info.status === WebEngineView.LoadFailedStatus) {
                    notice.text = "网页加载失败，可刷新或输入其他地址"
                    interactive.recordStage("load_failed", info.errorCode)
                }
            }
            onRenderProcessTerminated: function(status, exitCode) {
                notice.text = "网页进程已结束，可刷新重试"
                interactive.recordStage("render_process_terminated", exitCode)
            }
        }
        Rectangle {
            x: 0
            y: toolbar.height
            width: parent.width
            height: 28
            visible: notice.text.length > 0
            color: "#e0183040"
            Text { id: notice; anchors.centerIn: parent; text: ""; color: "white"; font.pixelSize: 19 }
        }
        BrowserKeyboard {
            id: keyboard
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            visible: false
            onCommitted: function(value) { interactive.typeText(value) }
            onBackspaceRequested: interactive.backspace()
            onEnterRequested: interactive.enter()
            onHideRequested: visible = false
        }
    }
}
