// SPDX-License-Identifier: GPL-3.0-or-later
// Independent, bounded browser experiment. No vendor IPC, shell or WebChannel.
#include <QtCore/QCommandLineParser>
#include <QtCore/QElapsedTimer>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QPointer>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtCore/QVariantMap>
#include <QtGui/QGuiApplication>
#include <QtGui/QImage>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>
#include <QtQuick/QQuickWindow>
#include <QtWebEngineCore/qtwebenginecoreglobal.h>
#include <QtWebEngineQuick/qtwebenginequickglobal.h>
#include <cstdio>
#include <cmath>
#include <memory>
#include <utility>
#include "interactive_controller.h"

namespace {
const QUrl kLocalPage(QStringLiteral("qrc:/p011-browser/home.html"));

QUrl publicSiteUrl(const QString &site)
{
    if (site == QStringLiteral("baidu"))
        return QUrl(QStringLiteral("https://www.baidu.com/"));
    if (site == QStringLiteral("bilibili"))
        return QUrl(QStringLiteral("https://www.bilibili.com/"));
    return QUrl();
}

void writeEvent(QJsonObject fields)
{
    fields.insert(QStringLiteral("schema"), 1);
    fields.insert(QStringLiteral("component"), QStringLiteral("p011-browser-probe"));
    const QByteArray line = QJsonDocument(fields).toJson(QJsonDocument::Compact);
    std::fwrite(line.constData(), 1, static_cast<size_t>(line.size()), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

bool validStartUrl(const QUrl &url)
{
    if (url == kLocalPage)
        return true;
    return url.isValid() && !url.isRelative() && url.scheme() == QStringLiteral("https")
        && !url.host().isEmpty() && url.userInfo().isEmpty();
}

bool validSessionDirectory(const QString &path)
{
    if (path.isEmpty())
        return true; // Standalone host smoke run: capture disabled.
    const QRegularExpression pattern(QStringLiteral(
        "\\A/mnt/data/p011-browser/sessions/[0-9]{8}-[0-9]{6}-[a-f0-9]{8}/app\\z"));
    const QFileInfo directory(path);
    return pattern.match(path).hasMatch() && directory.isDir()
        && !directory.isSymLink() && directory.canonicalFilePath() == path;
}
}

class ProbeController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QUrl startupUrl READ startupUrl CONSTANT)
    Q_PROPERTY(bool localProbe READ localProbe CONSTANT)
    Q_PROPERTY(QString publicSite READ publicSite CONSTANT)
public:
    explicit ProbeController(QUrl url, QString site, QString session, QObject *parent = nullptr)
        : QObject(parent), m_url(std::move(url)), m_site(std::move(site)), m_session(std::move(session)) { m_clock.start(); }
    QUrl startupUrl() const { return m_url; }
    bool localProbe() const { return m_url == kLocalPage; }
    QString publicSite() const { return m_site; }
    void setWindow(QQuickWindow *window) { m_window = window; }

    Q_INVOKABLE bool captureLocalWindow()
    {
        return localProbe() && captureWindow();
    }

    Q_INVOKABLE bool capturePublicWindow()
    {
        return !m_site.isEmpty() && captureWindow();
    }

    Q_INVOKABLE bool recordPublicMetrics(const QVariantMap &values)
    {
        if (m_site.isEmpty() || m_metricsRecorded)
            return false;
        static const QStringList booleanKeys = {QStringLiteral("ready_complete"), QStringLiteral("body_present")};
        static const QStringList numericKeys = {
            QStringLiteral("viewport_width"), QStringLiteral("viewport_height"),
            QStringLiteral("scroll_width"), QStringLiteral("scroll_height"),
            QStringLiteral("image_count"), QStringLiteral("loaded_image_count"), QStringLiteral("text_length")
        };
        if (values.size() != booleanKeys.size() + numericKeys.size())
            return metricsRejected();
        QJsonObject metrics;
        for (const QString &key : booleanKeys) {
            const QJsonValue value = QJsonValue::fromVariant(values.value(key));
            if (!value.isBool())
                return metricsRejected();
            metrics.insert(key, value);
        }
        for (const QString &key : numericKeys) {
            const QJsonValue value = QJsonValue::fromVariant(values.value(key));
            const double number = value.toDouble(-1);
            if (!value.isDouble() || !std::isfinite(number) || number < 0
                || number > 100000000 || std::floor(number) != number)
                return metricsRejected();
            metrics.insert(key, number);
        }
        m_metricsRecorded = true;
        writeEvent({{QStringLiteral("event"), QStringLiteral("public_page_metrics")},
                    {QStringLiteral("elapsed_ms"), m_clock.elapsed()},
                    {QStringLiteral("public_site"), m_site}, {QStringLiteral("metrics"), metrics}});
        return true;
    }

    // Called only from packaged QML. Web content has no bridge to this object.
    Q_INVOKABLE bool allowNavigation(const QUrl &url) const
    {
        if (localProbe())
            return url == kLocalPage;
        return !m_site.isEmpty() && validStartUrl(url)
            && url.host() == m_url.host() && url.port(443) == m_url.port(443);
    }

    Q_INVOKABLE void recordStage(const QString &stage, int detail = 0)
    {
        static const QStringList stages = {
            QStringLiteral("window_created"), QStringLiteral("window_visible"),
            QStringLiteral("first_frame_swapped"),
            QStringLiteral("load_started"), QStringLiteral("load_succeeded"),
            QStringLiteral("load_failed"), QStringLiteral("load_stopped"),
            QStringLiteral("render_process_terminated"), QStringLiteral("renderer_started"),
            QStringLiteral("navigation_denied"), QStringLiteral("permission_denied"),
            QStringLiteral("download_denied"), QStringLiteral("certificate_denied"),
            QStringLiteral("popup_denied"), QStringLiteral("file_dialog_denied"),
            QStringLiteral("dialog_denied"), QStringLiteral("protocol_handler_denied"),
            QStringLiteral("probe_pending"), QStringLiteral("dom_probe_result"),
            QStringLiteral("user_exit"), QStringLiteral("deadline_reached")
        };
        if (!stages.contains(stage))
            return;
        writeEvent({{QStringLiteral("event"), stage},
                    {QStringLiteral("elapsed_ms"), m_clock.elapsed()},
                    {QStringLiteral("detail"), qBound(-100000, detail, 100000)}});
    }

private:
    bool captureWindow()
    {
        if (m_captureAttempted || m_session.isEmpty() || !m_window)
            return false;
        m_captureAttempted = true;
        if (!validSessionDirectory(m_session))
            return captureFailed();
        const QString directory = m_session + QStringLiteral("/captures");
        const QString filename = localProbe() ? QStringLiteral("/local-fixture-window.png")
            : m_site == QStringLiteral("baidu") ? QStringLiteral("/public-baidu-window.png")
            : m_site == QStringLiteral("bilibili") ? QStringLiteral("/public-bilibili-window.png") : QString();
        if (filename.isEmpty())
            return captureFailed();
        const QString output = directory + filename;
        QDir(m_session).mkdir(QStringLiteral("captures"));
        const QFileInfo directoryInfo(directory);
        if (!directoryInfo.isDir() || directoryInfo.isSymLink()
            || directoryInfo.canonicalFilePath() != directory || QFileInfo::exists(output))
            return captureFailed();
        const QImage picture = m_window->grabWindow();
        if (picture.isNull() || !picture.save(output, "PNG"))
            return captureFailed();
        writeEvent({{QStringLiteral("event"), localProbe() ? QStringLiteral("local_capture_saved") : QStringLiteral("public_capture_saved")},
                    {QStringLiteral("elapsed_ms"), m_clock.elapsed()},
                    {QStringLiteral("public_site"), m_site},
                    {QStringLiteral("evidence_kind"), QStringLiteral("application-window")},
                    {QStringLiteral("physical_scanout_verified"), false},
                    {QStringLiteral("width"), picture.width()},
                    {QStringLiteral("height"), picture.height()}});
        return true;
    }

    bool captureFailed()
    {
        writeEvent({{QStringLiteral("event"), localProbe() ? QStringLiteral("local_capture_failed") : QStringLiteral("public_capture_failed")},
                    {QStringLiteral("elapsed_ms"), m_clock.elapsed()}});
        return false;
    }
    bool metricsRejected()
    {
        writeEvent({{QStringLiteral("event"), QStringLiteral("public_metrics_rejected")},
                    {QStringLiteral("elapsed_ms"), m_clock.elapsed()}});
        return false;
    }
    const QUrl m_url;
    const QString m_site;
    const QString m_session;
    QPointer<QQuickWindow> m_window;
    bool m_captureAttempted = false;
    bool m_metricsRecorded = false;
    QElapsedTimer m_clock;
};

int main(int argc, char *argv[])
{
    // Qt's official Qt Quick WebEngine initialization order, before application.
    QCoreApplication::setAttribute(Qt::AA_ShareOpenGLContexts);
    QtWebEngineQuick::initialize();
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("p011-browser-probe"));
    app.setApplicationVersion(QStringLiteral("0.1"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Bounded independent P011 Qt 6.8 browser probe"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({QStringLiteral("seconds"), QStringLiteral("Duration: probe 1..120, interactive 1..1800 seconds"),
                      QStringLiteral("seconds"), QStringLiteral("30")});
    parser.addOption({QStringLiteral("interactive"), QStringLiteral("Open the interactive browser, maximum 1800 seconds")});
    parser.addOption({QStringLiteral("public-site"), QStringLiteral("Fixed public site: baidu or bilibili"),
                      QStringLiteral("site")});
    parser.addOption({QStringLiteral("session"), QStringLiteral("Existing /mnt/data/p011-browser/sessions/TIMESTAMP-hex8/app output directory"),
                      QStringLiteral("directory")});
    if (!parser.parse(app.arguments()) || !parser.positionalArguments().isEmpty()) {
        writeEvent({{QStringLiteral("event"), QStringLiteral("invalid_arguments")}});
        return 64;
    }
    if (parser.isSet(QStringLiteral("help")))
        parser.showHelp();
    if (parser.isSet(QStringLiteral("version")))
        parser.showVersion();
    bool secondsOk = false;
    const bool interactiveMode = parser.isSet(QStringLiteral("interactive"));
    const int parsedSeconds = parser.value(QStringLiteral("seconds")).toInt(&secondsOk);
    const int seconds = interactiveMode && !parser.isSet(QStringLiteral("seconds")) ? 1800 : parsedSeconds;
    const QString site = parser.value(QStringLiteral("public-site"));
    const QUrl url = site.isEmpty() ? kLocalPage : publicSiteUrl(site);
    const QString session = parser.value(QStringLiteral("session"));
    if (!secondsOk || seconds < 1 || (!interactiveMode && seconds > 120)
        || (interactiveMode && (seconds > 1800 || parser.isSet(QStringLiteral("public-site")))) || !validStartUrl(url)
        || !validSessionDirectory(session)) {
        writeEvent({{QStringLiteral("event"), QStringLiteral("invalid_arguments")}});
        return 64;
    }

    if (interactiveMode) {
        InteractiveController controller;
        controller.recordIdentity(seconds);
        QQmlApplicationEngine interactiveEngine;
        interactiveEngine.rootContext()->setContextProperty(QStringLiteral("interactive"), &controller);
        QObject::connect(&interactiveEngine, &QQmlApplicationEngine::objectCreationFailed, &app, [&controller] {
            controller.recordStage(QStringLiteral("qml_creation_failed"));
            QCoreApplication::exit(70);
        }, Qt::QueuedConnection);
        QTimer interactiveDeadline;
        interactiveDeadline.setSingleShot(true);
        QObject::connect(&interactiveDeadline, &QTimer::timeout, &app, [&controller, &app] {
            controller.recordStage(QStringLiteral("deadline_reached"));
            app.quit();
        });
        interactiveDeadline.start(seconds * 1000);
        interactiveEngine.load(QUrl(QStringLiteral("qrc:/p011-browser/Interactive.qml")));
        if (!interactiveEngine.rootObjects().isEmpty())
            controller.setWindow(qobject_cast<QQuickWindow *>(interactiveEngine.rootObjects().constFirst()));
        const int code = app.exec();
        controller.recordStage(QStringLiteral("event_loop_ended"), code);
        return code;
    }

    writeEvent({{QStringLiteral("event"), QStringLiteral("runtime_identity")},
                {QStringLiteral("qt"), QString::fromLatin1(qVersion())},
                {QStringLiteral("webengine"), QString::fromLatin1(qWebEngineVersion())},
                {QStringLiteral("chromium"), QString::fromLatin1(qWebEngineChromiumVersion())},
                {QStringLiteral("chromium_security_patch"), QString::fromLatin1(qWebEngineChromiumSecurityPatchVersion())},
                {QStringLiteral("seconds"), seconds},
                {QStringLiteral("capture_enabled"), !session.isEmpty()},
                {QStringLiteral("local_probe"), url == kLocalPage},
                {QStringLiteral("public_site"), site},
                {QStringLiteral("pid"), QCoreApplication::applicationPid()}});
    ProbeController probe(url, site, session);
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("probe"), &probe);
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                     [] {
        writeEvent({{QStringLiteral("event"), QStringLiteral("qml_creation_failed")}});
        QCoreApplication::exit(70);
    }, Qt::QueuedConnection);
    QTimer deadline;
    deadline.setSingleShot(true);
    QObject::connect(&deadline, &QTimer::timeout, &app, [&] {
        probe.recordStage(QStringLiteral("deadline_reached"));
        app.quit();
    });
    // Bounds the event loop; the host supervisor also bounds startup/driver hangs.
    deadline.start(seconds * 1000);
    engine.load(QUrl(QStringLiteral("qrc:/p011-browser/Main.qml")));
    if (!engine.rootObjects().isEmpty()) {
        if (auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().constFirst())) {
            probe.setWindow(window);
            auto firstFrame = std::make_shared<bool>(false);
            QObject::connect(window, &QQuickWindow::frameSwapped, &app, [&, firstFrame] {
                if (!*firstFrame) {
                    *firstFrame = true;
                    probe.recordStage(QStringLiteral("first_frame_swapped"));
                }
            }, Qt::QueuedConnection);
        }
    }
    const int code = app.exec();
    writeEvent({{QStringLiteral("event"), QStringLiteral("event_loop_ended")},
                {QStringLiteral("exit_code"), code}});
    return code;
}

#include "main.moc"

