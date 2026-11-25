import QtQuick 2.10
import "MtaTheme.js" as Theme

Rectangle {
    id: page
    objectName: "mtaPage"
    width: 800; height: 268; color: Theme.background
    // The host supplies a loopback endpoint and token. Empty means unavailable,
    // never a fixture and never an instruction to start wireless services.
    property string serviceUrl: ""
    property string token: ""
    property bool hostPreview: false
    property bool nicknameEditorAvailable: false
    property var status: ({state: "unavailable", nickname: "P011", devices: [], received: [], capabilities: {}, reason: "互传服务未就绪"})
    property var selectedFiles: []
    property string selectedDeviceId: ""
    property string tab: "receive"
    property bool showingReceived: false
    property bool backendOnline: false
    property bool statusPending: false
    property bool actionPending: false
    property bool leaving: false
    property string connectionReason: "互传服务未就绪"
    property string message: ""
    property var lifetime: ({alive: true, epoch: 0})
    property var pending: []
    readonly property string currentState: backendOnline ? String(status.state || "idle") : "unavailable"
    readonly property bool transferring: currentState === "transferring" || currentState === "connecting"
    readonly property bool restoring: currentState === "restoring"
    readonly property bool hasRequest: !!(backendOnline && status.request && status.request.id)
    readonly property bool radioBusy: transferring || restoring || hasRequest
    readonly property bool discoveryBusy: activeDiscovery() || activeScan()
    readonly property var deviceRows: backendOnline && status.devices ? status.devices : []
    readonly property var receivedRows: backendOnline && status.received ? status.received : []
    readonly property var progress: status.transfer || ({})
    readonly property bool sending: backendOnline && progress.direction === "send"
    readonly property bool archiveProgressKnown: backendOnline && !sending && validProgressBytes(progress.archiveBytes)
    readonly property real progressRatio: Number(progress.totalBytes || 0) > 0 ? Math.max(0, Math.min(1, Number(progress.bytes || 0) / Number(progress.totalBytes))) : 0
    property string headerTitle: "手机互传"
    signal exitRequested()
    signal fileCenterRequested(string mode)
    signal nicknameEditRequested(string currentName)
    signal actionObserved(string action)

    function capability(name) {
        var value = (status.capabilities || {})[name];
        return !!(backendOnline && (value === true || (value && value.available === true)));
    }
    function capabilityReason(name) {
        var value = (status.capabilities || {})[name];
        return value && value.reason ? String(value.reason) : String(status.reason || "当前环境尚不支持此功能");
    }
    function activeDiscovery() {
        return status.discoverable === true || currentState === "advertising" || currentState === "discoverable";
    }
    function activeScan() {
        return status.scanning === true || currentState === "scanning";
    }
    function friendlyState() {
        var names = {unavailable: "暂不可用", idle: "准备就绪", advertising: "等待手机发现", discoverable: "等待手机发现", scanning: "正在查找设备", waiting: "等待连接", connecting: "正在连接", transferring: "正在传输", restoring: "正在恢复网络", complete: "传输完成", completed: "传输完成", error: "传输未完成", failed: "传输未完成", awaiting_confirmation: "收到文件请求"};
        if (currentState === "idle" && !capability("receive") && !capability("send")) return "互传暂不可用";
        if (hasRequest) return "收到文件请求";
        var sendWaiting = sendWaitingText();
        if (sendWaiting) return sendWaiting;
        return names[currentState] || "互传状态待核实";
    }
    function sendWaitingText() {
        // A stale transport stage must not override restoration or a terminal result.
        if (!sending || (currentState !== "connecting" && currentState !== "transferring")) return "";
        var stage = (status.sendLifecycle || {}).stage;
        return stage === "awaiting_confirmation" ? "等待对方确认" : stage === "awaiting_result" ? "等待完成结果" : "";
    }
    function validProgressBytes(value) {
        return typeof value === "number" && isFinite(value) && value >= 0 && Math.floor(value) === value;
    }
    function progressText() {
        // Downloaded ZIP bytes are separate from file-processing progress. No archive total is
        // supplied by the receive bridge, so do not manufacture a percentage.
        if (archiveProgressKnown) return "归档已下载 " + formatBytes(progress.archiveBytes);
        var text = formatBytes(progress.bytes) + " / " + formatBytes(progress.totalBytes);
        return sending && Number(progress.totalBytes || 0) > 0 ? text + " · " + (progressRatio * 100).toFixed(1) + "%" : text;
    }
    function progressDetails() {
        if (archiveProgressKnown) {
            if (!validProgressBytes(progress.bytes)) return "等待文件校验进度";
            var processing = "解包校验 " + formatBytes(progress.bytes);
            return validProgressBytes(progress.totalBytes) && progress.totalBytes > 0 ? processing + " / " + formatBytes(progress.totalBytes) : processing;
        }
        var total = progress.totalFiles, done = progress.filesDone;
        var totalKnown = typeof total === "number" && isFinite(total) && total >= 0 && Math.floor(total) === total;
        var doneKnown = typeof done === "number" && isFinite(done) && done >= 0 && Math.floor(done) === done;
        if (totalKnown && doneKnown && done <= total) return "已完成 " + done + " / " + total + " 个文件";
        if (totalKnown) return (sending ? "发送 " : "接收 ") + total + " 个文件";
        return sending ? "发送字节不代表对方已保存" : "等待文件进度";
    }
    function formatBytes(value) {
        var n = Math.max(0, Number(value || 0));
        if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GB";
        if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
        if (n >= 1024) return Math.ceil(n / 1024) + " KB";
        return Math.round(n) + " B";
    }
    function infoText() {
        if (!backendOnline) return connectionReason;
        if (hasRequest) return "请确认发送方与文件大小，再选择接受或拒绝";
        if (restoring) return "传输已结束，正在还原本次网络设置";
        if (status.reason) return String(status.reason);
        var sendWaiting = sendWaitingText();
        if (sendWaiting === "等待对方确认") return "请在对方设备上确认接收文件";
        if (sendWaiting === "等待完成结果") return "字节已发送，正在等待对方完成确认；请勿重复发送";
        if (activeDiscovery()) return "在手机原厂互传中选择本机；收到文件需确认";
        if (tab === "send") {
            if (!capability("scan") && !capability("send")) return capabilityReason("send");
            return selectedFiles.length ? "选择本轮在线设备，再点发送" : "先从文件中心选择要发送的文件";
        }
        if (!capability("receive")) return capabilityReason("receive");
        return "开启后允许临时连接手机 Wi-Fi；文件仍需确认，结束后恢复原网络";
    }
    function toast(text) { message = String(text || "操作未完成"); toastTimer.restart(); }
    function validEndpoint() {
        return /^http:\/\/127\.0\.0\.1(?::[0-9]{1,5})?$/.test(serviceUrl) && token.length > 0;
    }
    function request(path, form, done) {
        if (!validEndpoint() || leaving) { done(false, {reason: "互传服务未就绪"}); return; }
        var xhr = new XMLHttpRequest(), guard = lifetime, epoch = guard.epoch, finished = false;
        function finish(ok, value) {
            if (finished) return;
            finished = true;
            if (guard.alive && guard.epoch === epoch && done) done(ok, value);
        }
        xhr.onreadystatechange = function() {
            if (xhr.readyState !== XMLHttpRequest.DONE) return;
            try {
                var value = JSON.parse(xhr.responseText);
                var ok = xhr.status >= 200 && xhr.status < 300 && value.ok !== false;
                finish(ok, value.data || value.status || value);
            } catch (e) { finish(false, {reason: "连接中断，传输状态待核实"}); }
        };
        try {
            xhr.open(form === null ? "GET" : "POST", serviceUrl + path);
            xhr.setRequestHeader("X-P011-MTA-Token", token);
            if (form !== null) xhr.setRequestHeader("Content-Type", "application/json");
            pending.push({xhr: xhr, at: Date.now(), finished: function() { return finished; }, expire: function() { xhr.abort(); finish(false, {reason: "本地服务响应超时，状态待核实"}); }});
            xhr.send(form === null ? "" : JSON.stringify(form));
        } catch (e) { finish(false, {reason: "本地服务连接失败"}); }
    }
    function applyStatus(value) {
        if (!value || !value.state) { backendOnline = false; connectionReason = "互传服务返回异常，状态待核实"; return; }
        status = value; backendOnline = true; connectionReason = "";
        var found = false;
        for (var i = 0; i < deviceRows.length; i++) if (deviceRows[i].id === selectedDeviceId && deviceRows[i].available === true) found = true;
        if (!found) selectedDeviceId = "";
    }
    function refresh() {
        if (statusPending || leaving) return;
        statusPending = true;
        request("/v1/status", null, function(ok, value) {
            statusPending = false;
            if (ok) applyStatus(value);
            else { backendOnline = false; connectionReason = String(value.reason || value.error || "连接中断，传输状态待核实"); }
        });
    }
    function issue(action, fields) {
        if (actionPending || leaving || !backendOnline) return;
        var body = {action: action};
        fields = fields || {};
        for (var key in fields) body[key] = fields[key];
        actionPending = true; actionObserved(action);
        request("/v1/action", body, function(ok, value) {
            actionPending = false;
            if (ok) { if (value.state) applyStatus(value); else refresh(); }
            else { toast(value.reason || value.error || "操作未完成"); refresh(); }
        });
    }
    function applyNickname(value) {
        var name = String(value || "").replace(/^\s+|\s+$/g, "");
        if (!name) { toast("设备名称不能为空"); return; }
        if (!capability("rename") || radioBusy || actionPending) { toast("传输结束后再修改设备名称"); return; }
        issue("rename", {nickname: name});
    }
    function sendSelected() {
        if (!selectedDeviceId || !selectedFiles.length || !capability("send") || radioBusy) return;
        var ids = [];
        for (var i = 0; i < selectedFiles.length; i++) if (selectedFiles[i].id) ids.push(selectedFiles[i].id);
        if (ids.length !== selectedFiles.length) { toast("请在文件中心重新选择文件"); return; }
        issue("send", {deviceId: selectedDeviceId, fileIds: ids});
    }
    function handleBack() {
        if (message) { message = ""; return true; }
        if (showingReceived) { showingReceived = false; return true; }
        return false;
    }
    function prepareLeave() {
        leaving = true; lifetime.epoch++;
        for (var i = 0; i < pending.length; i++) pending[i].xhr.abort();
        pending = []; statusPending = false; actionPending = false;
    }
    function resetConnection() {
        // Late replies from an old token/service must not re-enable actions.
        lifetime.epoch++;
        for (var i = 0; i < pending.length; i++) pending[i].xhr.abort();
        pending = []; statusPending = false; actionPending = false;
        backendOnline = false; selectedDeviceId = "";
        connectionReason = validEndpoint() ? "正在连接本地互传服务" : "互传服务未就绪";
        if (validEndpoint() && !leaving) refresh();
    }
    onServiceUrlChanged: resetConnection()
    onTokenChanged: resetConnection()

    MtaButton { objectName: "mtaBack"; x: 8; y: 4; width: 104; height: 40; fontSize: 22; text: "‹ 返回"; onClicked: { if (!page.handleBack()) page.exitRequested(); } }
    MtaLabel { x: 132; y: 2; width: 180; height: 42; font.pixelSize: 28; text: "手机互传" }
    MtaLabel { objectName: "mtaPreviewBadge"; x: 308; y: 3; width: 170; height: 40; font.pixelSize: 18; color: Theme.warning; text: "HOST · 界面测试"; visible: page.hostPreview }
    MtaLabel { objectName: "mtaNickname"; x: page.hostPreview ? 480 : 330; y: 3; width: page.hostPreview ? 180 : 330; height: 40; font.pixelSize: 21; color: Theme.secondary; text: String(page.status.nickname || "P011"); elide: Text.ElideRight }
    MtaButton { objectName: "mtaRename"; x: 676; y: 4; width: 116; height: 40; text: "改名"; fontSize: 22; enabled: page.nicknameEditorAvailable && page.capability("rename") && !page.radioBusy && !page.discoveryBusy && !page.actionPending; onClicked: page.nicknameEditRequested(String(page.status.nickname || "P011")) }

    Column {
        x: 8; y: 52; spacing: 8
        MtaButton { objectName: "mtaReceiveTab"; width: 104; height: 54; text: "接收"; accent: page.tab === "receive"; enabled: !page.radioBusy && !page.actionPending && (!page.discoveryBusy || page.tab==="receive"); onClicked: { page.tab = "receive"; page.showingReceived = false; } }
        MtaButton { objectName: "mtaSendTab"; width: 104; height: 54; text: "发送"; accent: page.tab === "send"; enabled: !page.radioBusy && !page.actionPending && (!page.discoveryBusy || page.tab==="send"); onClicked: { page.tab = "send"; page.showingReceived = false; } }
        MtaButton { objectName: "mtaFiles"; width: 104; height: 82; text: page.tab === "send" ? "选文件" : "文件中心"; fontSize: 22; enabled: !page.radioBusy; onClicked: page.fileCenterRequested(page.tab === "send" ? "select" : "received") }
    }
    Rectangle {
        x: 124; y: 52; width: 540; height: 208; radius: Theme.radius; color: Theme.row
        MtaLabel { objectName: "mtaState"; x: 12; y: 2; width: 516; height: 36; text: page.friendlyState(); font.pixelSize: 25; color: page.currentState === "unavailable" || page.currentState === "error" || page.currentState === "failed" ? Theme.warning : Theme.accent }
        MtaLabel { objectName: "mtaInfo"; x: 12; y: 39; width: 516; height: 44; text: page.infoText(); wrapMode: Text.Wrap; maximumLineCount: 2; elide: Text.ElideRight; font.pixelSize: 18; color: Theme.secondary }

        Item {
            x: 12; y: 89; width: 516; height: 108
            visible: page.hasRequest
            MtaLabel { y: 0; width: parent.width; height: 37; font.pixelSize: 25; text: "来自 " + String((page.status.request || {}).name || "未命名设备"); elide: Text.ElideRight }
            MtaLabel { y: 39; width: parent.width; height: 32; font.pixelSize: 22; text: String((page.status.request || {}).fileCount || 0) + " 个文件 · " + page.formatBytes((page.status.request || {}).totalBytes) }
            MtaLabel { y: 75; width: parent.width; height: 28; font.pixelSize: 17; color: Theme.secondary; text: "仅接受你认识的发送设备；文件保存到接收目录" }
        }
        Item {
            x: 12; y: 90; width: 516; height: 108
            visible: !page.hasRequest && (page.transferring || page.restoring)
            MtaLabel { objectName: "mtaProgressText"; y: 0; width: parent.width; height: 35; font.pixelSize: 24; text: page.restoring ? "网络恢复后即可继续使用" : page.progressText() }
            Rectangle { objectName: "mtaProgressTrack"; y: 45; width: parent.width; height: 12; radius: 6; color: Theme.button; Rectangle { width: parent.width * page.progressRatio; height: 12; radius: 6; color: Theme.accent } }
            MtaLabel { objectName: "mtaProgressDetails"; y: 68; width: parent.width; height: 32; font.pixelSize: 20; color: Theme.secondary; text: page.restoring ? "请勿关闭服务或再次开关无线功能" : page.progressDetails() }
        }
        ListView {
            id: deviceList; objectName: "mtaDeviceList"; x: 8; y: 87; width: 524; height: 113; clip: true; spacing: 5
            visible: !page.hasRequest && !page.transferring && !page.restoring && !page.showingReceived && page.tab === "send"
            model: page.deviceRows
            delegate: Rectangle {
                objectName: "mtaDevice" + index
                width: deviceList.width; height: 64; radius: 8
                color: modelData.id === page.selectedDeviceId ? "#163e37" : Theme.background
                border.color: modelData.id === page.selectedDeviceId ? Theme.accent : "transparent"
                opacity: modelData.available === true ? 1 : 0.55
                MtaLabel { x: 10; y: 3; width: 447; height: 34; text: String(modelData.name || "未命名设备"); font.pixelSize: 24; elide: Text.ElideRight }
                MtaLabel { x: 10; y: 37; width: 470; height: 24; text: modelData.available === true ? (page.capability("send") ? "本轮发现 · 可发送" : "本轮发现 · 发送尚未就绪") : "已离线 · 请重新搜索"; color: Theme.secondary; font.pixelSize: 17 }
                MtaLabel { x: 480; y: 3; width: 34; height: 57; text: modelData.id === page.selectedDeviceId ? "✓" : "›"; horizontalAlignment: Text.AlignHCenter; color: Theme.accent }
                MouseArea { anchors.fill: parent; enabled: modelData.available === true && !page.actionPending && page.capability("send"); onClicked: page.selectedDeviceId = modelData.id }
            }
            MtaLabel { anchors.fill: parent; visible: page.deviceRows.length === 0; text: page.backendOnline ? (page.activeScan() ? "保持手机互传开启，正在查找…" : "尚未发现设备，点右侧搜索") : "服务未连接，不显示历史设备"; font.pixelSize: 21; color: Theme.secondary; wrapMode: Text.Wrap; horizontalAlignment: Text.AlignHCenter }
        }
        Item {
            x: 12; y: 87; width: 516; height: 112
            visible: !page.hasRequest && !page.transferring && !page.restoring && !page.showingReceived && page.tab === "receive"
            MtaLabel { x: 0; y: 9; width: parent.width; height: 42; text: page.activeDiscovery() ? "等待手机发来文件" : page.capability("receive") ? "可发现已关闭" : "接收能力尚未就绪"; font.pixelSize: 27; horizontalAlignment: Text.AlignHCenter }
            MtaLabel { x: 0; y: 58; width: parent.width; height: 48; text: page.activeDiscovery() ? "无需配对；传输期间网络可能短暂切换" : "不会自动广播，也不会自动接收文件"; font.pixelSize: 20; color: Theme.secondary; wrapMode: Text.Wrap; horizontalAlignment: Text.AlignHCenter }
        }
        ListView {
            id: receivedList; objectName: "mtaReceivedList"; x: 8; y: 87; width: 524; height: 113; clip: true; spacing: 5
            visible: page.showingReceived && !page.hasRequest && !page.transferring && !page.restoring
            model: page.receivedRows
            delegate: Rectangle {
                width: receivedList.width; height: 62; radius: 8; color: Theme.background
                MtaLabel { x: 10; y: 2; width: parent.width - 20; height: 34; text: String(modelData.name || "未命名文件"); font.pixelSize: 23; elide: Text.ElideMiddle }
                MtaLabel { x: 10; y: 35; width: parent.width - 20; height: 24; text: page.formatBytes(modelData.size); font.pixelSize: 18; color: Theme.secondary }
            }
            MtaLabel { anchors.fill: parent; text: "尚无接收记录"; visible: page.receivedRows.length === 0; horizontalAlignment: Text.AlignHCenter; color: Theme.secondary }
        }
    }
    Column {
        x: 676; y: 52; spacing: 8
        MtaButton {
            objectName: "mtaPrimary"; width: 116; height: 72; accent: true
            text: page.hasRequest ? "接受" : page.transferring ? "取消传输" : page.tab === "receive" ? (page.activeDiscovery() ? "停止接收" : "开始接收") : (page.activeScan() ? "停止搜索" : "搜索")
            fontSize: 22
            enabled: !page.actionPending && !page.restoring && page.backendOnline && (page.hasRequest || page.transferring || page.capability(page.tab === "receive" ? "receive" : "scan"))
            onClicked: {
                if (page.hasRequest) page.issue("accept", {requestId: page.status.request.id});
                else if (page.transferring) page.issue("cancel");
                else if (page.tab === "receive") page.issue(page.activeDiscovery() ? "discover_stop" : "discover_start");
                else page.issue(page.activeScan() ? "scan_stop" : "scan");
            }
        }
        MtaButton {
            objectName: "mtaSecondary"; width: 116; height: 66; fontSize: 22
            text: page.hasRequest ? "拒绝" : page.tab === "receive" ? (page.showingReceived ? "收文件" : "已收到") : "发送文件"
            enabled: !page.actionPending && !page.transferring && !page.restoring && page.backendOnline && (page.hasRequest || page.tab === "receive" || (page.selectedDeviceId !== "" && page.selectedFiles.length > 0 && page.capability("send")))
            onClicked: {
                if (page.hasRequest) page.issue("reject", {requestId: page.status.request.id});
                else if (page.tab === "receive") page.showingReceived = !page.showingReceived;
                else page.sendSelected();
            }
        }
        MtaButton { objectName: "mtaRefresh"; width: 116; height: 54; fontSize: 21; text: page.status.restorePending ? "检查恢复" : page.tab === "send" && page.selectedFiles.length ? "已选 " + page.selectedFiles.length : "刷新状态"; enabled: !page.statusPending && !page.actionPending; onClicked: { if(page.status.restorePending)page.issue("recover");else if (page.tab === "send" && page.selectedFiles.length) page.fileCenterRequested("select"); else page.refresh(); } }
    }
    Rectangle {
        objectName: "mtaToast"; x: 120; y: 178; width: 548; height: 80; radius: 8; z: 40; color: "#f02f313b"; visible: page.message !== ""
        MtaLabel { anchors.fill: parent; anchors.margins: 12; text: page.message; font.pixelSize: 22; wrapMode: Text.Wrap; maximumLineCount: 2; elide: Text.ElideRight }
        MouseArea { anchors.fill: parent; onClicked: page.message = "" }
    }
    Timer { id: toastTimer; interval: 4500; onTriggered: page.message = "" }
    Timer { objectName: "mtaPollTimer"; interval: 1200; repeat: true; running: page.visible && !page.leaving && page.validEndpoint(); onTriggered: page.refresh() }
    Timer {
        interval: 400; repeat: true; running: !page.leaving
        onTriggered: {
            var keep = [];
            for (var i = 0; i < page.pending.length; i++) { var item = page.pending[i]; if (item.finished()) continue; if (Date.now() - item.at > 6000) item.expire(); else keep.push(item); }
            page.pending = keep;
        }
    }
    Keys.onEscapePressed: if (!handleBack()) exitRequested()
    Component.onCompleted: refresh()
    Component.onDestruction: { lifetime.alive = false; for (var i = 0; i < pending.length; i++) pending[i].xhr.abort(); }
}
