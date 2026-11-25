#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QOpenGLContext>
#include <QOpenGLFunctions>
#include <QSurfaceFormat>
#include <QTimer>
#include <QWindow>
#include <cstdio>

static void printEvent(const QJsonObject &value)
{
    const QByteArray body = QJsonDocument(value).toJson(QJsonDocument::Compact);
    std::fwrite(body.constData(), 1, size_t(body.size()), stdout);
    std::fwrite("\n", 1, 1, stdout);
    std::fflush(stdout);
}

class ProbeWindow final : public QWindow
{
public:
    bool attempted = false;
    bool rendered = false;
    QOpenGLContext context;

    void exposeEvent(QExposeEvent *) override
    {
        if (attempted || !isExposed())
            return;
        attempted = true;
        printEvent({{"event", "browser685.qt_gui"}, {"qt_version", qVersion()},
               {"platform", QGuiApplication::platformName()}, {"surface_exposed", true}});
        context.setFormat(requestedFormat());
        const bool created = context.create();
        const bool current = created && context.makeCurrent(this);
        QJsonObject result{{"event", "browser685.qt_gles"},
                           {"context_created", created}, {"make_current", current}};
        if (current) {
            auto *gl = context.functions();
            gl->initializeOpenGLFunctions();
            const auto string = [gl](GLenum key) {
                const GLubyte *value = gl->glGetString(key);
                return value ? QString::fromLatin1(reinterpret_cast<const char *>(value)) : QString();
            };
            result.insert("vendor", string(GL_VENDOR));
            result.insert("renderer", string(GL_RENDERER));
            result.insert("gl_version", string(GL_VERSION));
            gl->glViewport(0, 0, width(), height());
            gl->glClearColor(0.025f, 0.065f, 0.12f, 1.0f);
            gl->glClear(GL_COLOR_BUFFER_BIT);
            gl->glEnable(GL_SCISSOR_TEST);
            gl->glScissor(0, 106, 800, 268);
            gl->glClearColor(0.04f, 0.32f, 0.18f, 1.0f);
            gl->glClear(GL_COLOR_BUFFER_BIT);
            gl->glDisable(GL_SCISSOR_TEST);
            const GLenum error = gl->glGetError();
            context.swapBuffers(this);
            result.insert("gl_error", int(error));
            rendered = error == GL_NO_ERROR;
            result.insert("swap_called", true);
            context.doneCurrent();
        }
        printEvent(result);
    }
};

int main(int argc, char **argv)
{
    QSurfaceFormat format;
    format.setRenderableType(QSurfaceFormat::OpenGLES);
    format.setVersion(2, 0);
    format.setSwapInterval(1);
    QSurfaceFormat::setDefaultFormat(format);
    QGuiApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    ProbeWindow window;
    window.setTitle(QStringLiteral("Browser685 finite graphics probe"));
    window.setFlags(Qt::FramelessWindowHint);
    window.setSurfaceType(QSurface::OpenGLSurface);
    window.setFormat(format);
    window.resize(800, 480);
    window.show();
    QTimer::singleShot(900, &app, [&] {
        printEvent({{"event", "browser685.qt_gui_done"}, {"rendered", window.rendered},
               {"expose_attempted", window.attempted}});
        window.close();
        app.exit(window.rendered ? 0 : 2);
    });
    return app.exec();
}
