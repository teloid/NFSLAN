#include <QApplication>
#include <cstring>

#include "MainWindow.h"

#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
int NFSLANWorkerMain(int argc, char* argv[]);
#endif

int main(int argc, char* argv[])
{
#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
    if (argc > 1 && std::strcmp(argv[1], "--worker") == 0)
    {
        return NFSLANWorkerMain(argc - 1, argv + 1);
    }
#endif

    QApplication app(argc, argv);
    app.setApplicationName("NFSLAN GUI");
    app.setOrganizationName("NFSLAN");

    MainWindow window;
    window.show();

    return app.exec();
}
