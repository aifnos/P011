// SPDX-License-Identifier: GPL-3.0-or-later
#include "interactive_controller.h"
#include <QtCore/QCoreApplication>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QStringList>
#include <QtGui/QInputMethodEvent>
#include <QtGui/QKeyEvent>
#include <QtNetwork/QHostAddress>
#include <QtQuick/QQuickItem>
#include <QtWebEngineCore/qtwebenginecoreglobal.h>
#include <cstdio>

namespace {
void writeInteractiveEvent(QJsonObject fields)
{
    fields.insert(QStringLiteral("schema"), 1);
    fields.insert(QStringLiteral("component"), QStringLiteral("p011-browser-interactive"));
    const QByteArray data = QJsonDocument(fields).toJson(QJsonDocument::Compact);
    std::fwrite(data.constData(), 1, static_cast<size_t>(data.size()), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}
}

InteractiveController::InteractiveController(QObject *parent) : QObject(parent) {}
QUrl InteractiveController::startupUrl() const { return QUrl(QStringLiteral("https://www.baidu.com/")); }
void InteractiveController::setWindow(QQuickWindow *window) { m_window = window; }

void InteractiveController::recordIdentity(int seconds) const
{
    writeInteractiveEvent({{QStringLiteral("event"), QStringLiteral("runtime_identity")},
           {QStringLiteral("qt"), QString::fromLatin1(qVersion())},
           {QStringLiteral("webengine"), QString::fromLatin1(qWebEngineVersion())},
           {QStringLiteral("chromium"), QString::fromLatin1(qWebEngineChromiumVersion())},
           {QStringLiteral("interactive"), true}, {QStringLiteral("seconds"), seconds},
           {QStringLiteral("capture_enabled"), false}, {QStringLiteral("automatic_dom_probe"), false}});
}

bool InteractiveController::allowNavigation(const QUrl &url) const
{
    const QString scheme = url.scheme().toLower();
    const QString host = url.host().toLower();
    if (!url.isValid() || url.isRelative() || (scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))
        || host.isEmpty() || !url.userInfo().isEmpty() || url.port(1) == 0
        || host == QStringLiteral("localhost") || host.endsWith(QStringLiteral(".localhost")))
        return false;
    QHostAddress address;
    if (address.setAddress(host)) {
        bool ipv4 = false;
        const quint32 value = address.toIPv4Address(&ipv4);
        if (ipv4 && !host.contains(QLatin1Char(':'))
            && !QRegularExpression(QStringLiteral("\\A(?:0|[1-9][0-9]{0,2})(?:\\.(?:0|[1-9][0-9]{0,2})){3}\\z")).match(host).hasMatch())
            return false;
        if (address.isLoopback() || address.isLinkLocal() || address.isNull()
            || address == QHostAddress(QHostAddress::Any) || address == QHostAddress(QHostAddress::AnyIPv6)
            || (ipv4 && ((value >> 24) == 127 || (value >> 24) == 0 || (value >> 16) == 0xa9fe)))
            return false;
    } else if (QRegularExpression(QStringLiteral("\\A(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\\.(?:0[xX][0-9a-fA-F]+|[0-9]+))*\\z")).match(host).hasMatch()) {
        // Reject legacy numeric/hex/octal host spellings before Chromium can
        // canonicalize them to a loopback or another local control endpoint.
        return false;
    }
    return true;
}

QUrl InteractiveController::addressFor(const QString &input) const
{
    QString value = input.trimmed();
    if (value.isEmpty() || value.size() > 2048
        || QRegularExpression(QStringLiteral("[\\x00-\\x20\\x7f]")).match(value).hasMatch())
        return QUrl();
    if (!value.contains(QStringLiteral("://")))
        value.prepend(QStringLiteral("https://"));
    const QUrl url(value, QUrl::StrictMode);
    return allowNavigation(url) ? url : QUrl();
}

void InteractiveController::typeText(const QString &text)
{
    if (!m_window || text.isEmpty() || text.size() > 32)
        return;
    QQuickItem *target = m_window->activeFocusItem();
    if (!target || target->window() != m_window)
        return;
    QInputMethodEvent input;
    input.setCommitString(text);
    QCoreApplication::sendEvent(target, &input);
}

void InteractiveController::key(int value, const QString &text)
{
    if (!m_window)
        return;
    QKeyEvent press(QEvent::KeyPress, value, Qt::NoModifier, text);
    QKeyEvent release(QEvent::KeyRelease, value, Qt::NoModifier, text);
    QCoreApplication::sendEvent(m_window, &press);
    QCoreApplication::sendEvent(m_window, &release);
}
void InteractiveController::backspace() { key(Qt::Key_Backspace, QString()); }
void InteractiveController::enter() { key(Qt::Key_Return, QStringLiteral("\r")); }

void InteractiveController::recordStage(const QString &stage, int detail) const
{
    static const QStringList allowed = {
        QStringLiteral("window_created"), QStringLiteral("load_started"), QStringLiteral("load_succeeded"),
        QStringLiteral("load_failed"), QStringLiteral("navigation_denied"), QStringLiteral("certificate_denied"),
        QStringLiteral("permission_denied"), QStringLiteral("download_denied"), QStringLiteral("popup_denied"),
        QStringLiteral("file_dialog_denied"), QStringLiteral("dialog_denied"), QStringLiteral("protocol_handler_denied"),
        QStringLiteral("render_process_terminated"), QStringLiteral("user_exit"), QStringLiteral("deadline_reached"),
        QStringLiteral("qml_creation_failed"), QStringLiteral("event_loop_ended")
    };
    if (allowed.contains(stage))
        writeInteractiveEvent({{QStringLiteral("event"), stage}, {QStringLiteral("detail"), qBound(-100000, detail, 100000)}});
}
