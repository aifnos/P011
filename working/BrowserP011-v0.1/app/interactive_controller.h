// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QtCore/QObject>
#include <QtCore/QPointer>
#include <QtCore/QUrl>
#include <QtQuick/QQuickWindow>

class InteractiveController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QUrl startupUrl READ startupUrl CONSTANT)
public:
    explicit InteractiveController(QObject *parent = nullptr);
    QUrl startupUrl() const;
    void setWindow(QQuickWindow *window);
    void recordIdentity(int seconds) const;
    Q_INVOKABLE QUrl addressFor(const QString &input) const;
    Q_INVOKABLE bool allowNavigation(const QUrl &url) const;
    Q_INVOKABLE void typeText(const QString &text);
    Q_INVOKABLE void backspace();
    Q_INVOKABLE void enter();
    Q_INVOKABLE void recordStage(const QString &stage, int detail = 0) const;
private:
    void key(int value, const QString &text);
    QPointer<QQuickWindow> m_window;
};
