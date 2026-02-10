#include "MainWindow.h"

#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSettings>
#include <QStringList>
#include <QStandardPaths>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>

namespace
{
constexpr int kStartTimeoutMs = 5000;
constexpr int kStopTimeoutMs = 3000;

QString processErrorToString(QProcess::ProcessError error)
{
    switch (error)
    {
    case QProcess::FailedToStart:
        return QStringLiteral("Failed to start");
    case QProcess::Crashed:
        return QStringLiteral("Crashed");
    case QProcess::Timedout:
        return QStringLiteral("Timed out");
    case QProcess::ReadError:
        return QStringLiteral("Read error");
    case QProcess::WriteError:
        return QStringLiteral("Write error");
    case QProcess::UnknownError:
    default:
        return QStringLiteral("Unknown error");
    }
}

QString profileLabelToKey(const QString& gameId)
{
    if (gameId == QStringLiteral("ug2"))
    {
        return QStringLiteral("Underground2");
    }

    return QStringLiteral("MostWanted");
}

QStringList normalizedRuntimeCommand(const QString& input)
{
    const QString raw = input.trimmed().isEmpty() ? QStringLiteral("wine") : input.trimmed();
    QStringList parts = QProcess::splitCommand(raw);
    if (parts.isEmpty())
    {
        parts << QStringLiteral("wine");
    }
    return parts;
}
} // namespace

MainWindow::MainWindow()
    : process_(new QProcess(this))
    , gameCombo_(new QComboBox(this))
    , serverNameEdit_(new QLineEdit(this))
    , serverDirectoryEdit_(new QLineEdit(this))
    , workerBinaryEdit_(new QLineEdit(this))
    , wineBinaryEdit_(new QLineEdit(this))
    , startButton_(new QPushButton(QStringLiteral("Start Server"), this))
    , stopButton_(new QPushButton(QStringLiteral("Stop Server"), this))
    , logView_(new QTextEdit(this))
    , statusLabel_(new QLabel(this))
    , disablePatchingCheck_(new QCheckBox(QStringLiteral("Disable binary patching (-n)"), this))
    , clearLogOnStartCheck_(new QCheckBox(QStringLiteral("Clear logs on each start"), this))
{
    setWindowTitle(QStringLiteral("NFSLAN Server Manager"));
    resize(980, 680);

    gameCombo_->addItem(QStringLiteral("Need for Speed Most Wanted (2005)"), QStringLiteral("mw"));
    gameCombo_->addItem(QStringLiteral("Need for Speed Underground 2"), QStringLiteral("ug2"));

#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
    const QString note = QStringLiteral(
        "Single executable mode is enabled: this GUI starts the embedded worker runtime "
        "inside the same EXE.");
#elif defined(Q_OS_WIN)
    const QString note = QStringLiteral(
        "Run one game server per instance. This GUI launches a separate worker executable on Windows.");
#else
    const QString note = QStringLiteral(
        "Run one game server per instance. Non-Windows hosts launch the Windows worker through "
        "a runtime command (for example wine, or a Proton wrapper script).");
#endif

    auto* rootWidget = new QWidget(this);
    auto* rootLayout = new QVBoxLayout(rootWidget);
    rootWidget->setLayout(rootLayout);
    setCentralWidget(rootWidget);

    auto* noteLabel = new QLabel(note, this);
    noteLabel->setWordWrap(true);
    rootLayout->addWidget(noteLabel);

    auto* formLayout = new QFormLayout();
    formLayout->addRow(QStringLiteral("Game profile"), gameCombo_);
    formLayout->addRow(QStringLiteral("Server name"), serverNameEdit_);

    auto* serverDirRow = new QWidget(this);
    auto* serverDirLayout = new QHBoxLayout(serverDirRow);
    serverDirLayout->setContentsMargins(0, 0, 0, 0);
    auto* browseServerDirectoryButton = new QPushButton(QStringLiteral("Browse..."), this);
    serverDirLayout->addWidget(serverDirectoryEdit_);
    serverDirLayout->addWidget(browseServerDirectoryButton);
    formLayout->addRow(QStringLiteral("Server directory"), serverDirRow);

    auto* workerRow = new QWidget(this);
    auto* workerLayout = new QHBoxLayout(workerRow);
    workerLayout->setContentsMargins(0, 0, 0, 0);
    auto* browseWorkerButton = new QPushButton(QStringLiteral("Browse..."), this);
    workerLayout->addWidget(workerBinaryEdit_);
    workerLayout->addWidget(browseWorkerButton);
    formLayout->addRow(QStringLiteral("Worker executable"), workerRow);

#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
    workerBinaryEdit_->setText(QStringLiteral("(embedded in this executable)"));
    workerBinaryEdit_->setEnabled(false);
    browseWorkerButton->setEnabled(false);
#endif

    formLayout->addRow(QStringLiteral("Runtime command"), wineBinaryEdit_);

#if defined(Q_OS_WIN)
    wineBinaryEdit_->setText(QStringLiteral("(not used on Windows)"));
    wineBinaryEdit_->setEnabled(false);
#else
    wineBinaryEdit_->setPlaceholderText(QStringLiteral("wine"));
#endif

    rootLayout->addLayout(formLayout);
    rootLayout->addWidget(disablePatchingCheck_);
    rootLayout->addWidget(clearLogOnStartCheck_);

    auto* controlsLayout = new QHBoxLayout();
    controlsLayout->addWidget(startButton_);
    controlsLayout->addWidget(stopButton_);
    controlsLayout->addStretch(1);
    rootLayout->addLayout(controlsLayout);

    statusLabel_->setText(QStringLiteral("Status: stopped"));
    rootLayout->addWidget(statusLabel_);

    logView_->setReadOnly(true);
    rootLayout->addWidget(logView_, 1);

    connect(startButton_, &QPushButton::clicked, this, &MainWindow::startServer);
    connect(stopButton_, &QPushButton::clicked, this, &MainWindow::stopServer);
    connect(browseServerDirectoryButton, &QPushButton::clicked, this, &MainWindow::browseServerDirectory);
    connect(browseWorkerButton, &QPushButton::clicked, this, &MainWindow::browseWorkerBinary);

    connect(process_, &QProcess::readyReadStandardOutput, this, &MainWindow::readProcessOutput);
    connect(process_, &QProcess::readyReadStandardError, this, &MainWindow::readProcessOutput);
    connect(process_, &QProcess::errorOccurred, this, &MainWindow::onProcessError);
    connect(process_, &QProcess::stateChanged, this, [this](QProcess::ProcessState) {
        updateUiState();
    });
    connect(
        process_,
        static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
        this,
        &MainWindow::onProcessFinished);

    loadSettings();

    connect(gameCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, &MainWindow::onGameProfileChanged);

    updateUiState();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (process_->state() != QProcess::NotRunning)
    {
        stopServer();
    }

    saveSettings();
    QMainWindow::closeEvent(event);
}

void MainWindow::startServer()
{
    if (process_->state() != QProcess::NotRunning)
    {
        return;
    }

    QString errorMessage;
    if (!validateStartInputs(&errorMessage))
    {
        QMessageBox::critical(this, QStringLiteral("Cannot start server"), errorMessage);
        return;
    }

    saveSettings();

    if (clearLogOnStartCheck_->isChecked())
    {
        logView_->clear();
    }

    QString program;
    QStringList args;
    QStringList workerArgs;

    workerArgs << serverNameEdit_->text().trimmed();

    if (disablePatchingCheck_->isChecked())
    {
        workerArgs << QStringLiteral("-n");
    }

#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
    program = QCoreApplication::applicationFilePath();
    args << QStringLiteral("--worker");
    args.append(workerArgs);
#elif defined(Q_OS_WIN)
    program = selectedWorkerBinary();
    args = workerArgs;
#else
    QStringList runtimeCommand = normalizedRuntimeCommand(wineBinaryEdit_->text());
    program = runtimeCommand.takeFirst();
    args = runtimeCommand;
    args << selectedWorkerBinary();
    args.append(workerArgs);
#endif

    process_->setWorkingDirectory(selectedServerDirectory());
    process_->setProgram(program);
    process_->setArguments(args);
    process_->setProcessChannelMode(QProcess::MergedChannels);

    appendLogLine(
        QStringLiteral("Starting %1 %2")
            .arg(program, args.join(QLatin1Char(' '))));

    process_->start();

    if (!process_->waitForStarted(kStartTimeoutMs))
    {
        appendLogLine(QStringLiteral("Worker did not start: %1").arg(process_->errorString()));
        QMessageBox::critical(this, QStringLiteral("Cannot start server"), process_->errorString());
        updateUiState();
        return;
    }

    appendLogLine(
        QStringLiteral("Profile: %1")
            .arg(profileLabelToKey(currentProfileKey())));
    appendLogLine(QStringLiteral("Server started"));

    updateUiState();
}

void MainWindow::stopServer()
{
    if (process_->state() == QProcess::NotRunning)
    {
        updateUiState();
        return;
    }

    appendLogLine(QStringLiteral("Stopping server process"));
    process_->terminate();

    if (!process_->waitForFinished(kStopTimeoutMs))
    {
        appendLogLine(QStringLiteral("Worker did not exit cleanly, forcing termination"));
        process_->kill();
        process_->waitForFinished(kStopTimeoutMs);
    }

    updateUiState();
}

void MainWindow::browseServerDirectory()
{
    const QString selected = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("Select server directory"),
        selectedServerDirectory());

    if (!selected.isEmpty())
    {
        serverDirectoryEdit_->setText(selected);
        saveProfile(currentProfileKey());
    }
}

void MainWindow::browseWorkerBinary()
{
#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
    return;
#endif

#if defined(Q_OS_WIN)
    const QString filter = QStringLiteral("Worker executable (NFSLAN*.exe);;All files (*)");
#else
    const QString filter = QStringLiteral("Worker executable (*.exe);;All files (*)");
#endif

    const QString selected = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Select worker executable"),
        selectedWorkerBinary(),
        filter);

    if (!selected.isEmpty())
    {
        workerBinaryEdit_->setText(selected);
    }
}

void MainWindow::updateUiState()
{
    const bool running = (process_->state() != QProcess::NotRunning);

    startButton_->setEnabled(!running);
    stopButton_->setEnabled(running);

    gameCombo_->setEnabled(!running);
    serverNameEdit_->setEnabled(!running);
    serverDirectoryEdit_->setEnabled(!running);
#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
    workerBinaryEdit_->setEnabled(false);
#else
    workerBinaryEdit_->setEnabled(!running);
#endif
#if !defined(Q_OS_WIN)
    wineBinaryEdit_->setEnabled(!running);
#endif
    disablePatchingCheck_->setEnabled(!running);

    if (running)
    {
        statusLabel_->setText(QStringLiteral("Status: running"));
    }
    else
    {
        statusLabel_->setText(QStringLiteral("Status: stopped"));
    }
}

void MainWindow::readProcessOutput()
{
    const QByteArray output = process_->readAll();
    if (output.isEmpty())
    {
        return;
    }

    const QString text = QString::fromLocal8Bit(output)
                             .replace(QStringLiteral("\r\n"), QStringLiteral("\n"))
                             .replace(QLatin1Char('\r'), QLatin1Char('\n'));

    const QStringList lines = text.split(QLatin1Char('\n'), Qt::SkipEmptyParts);

    for (const QString& line : lines)
    {
        appendLogLine(line);
    }
}

void MainWindow::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    QString details = QStringLiteral("Worker exited with code %1").arg(exitCode);
    if (exitStatus == QProcess::CrashExit)
    {
        details += QStringLiteral(" (crashed)");
    }

    appendLogLine(details);
    updateUiState();
}

void MainWindow::onProcessError(QProcess::ProcessError error)
{
    appendLogLine(
        QStringLiteral("Worker error: %1 (%2)")
            .arg(processErrorToString(error), process_->errorString()));
    updateUiState();
}

void MainWindow::onGameProfileChanged(int)
{
    const QString nextProfile = currentProfileKey();

    if (!activeProfileKey_.isEmpty())
    {
        saveProfile(activeProfileKey_);
    }

    activeProfileKey_ = nextProfile;
    loadProfile(activeProfileKey_);
}

QString MainWindow::currentProfileKey() const
{
    return gameCombo_->currentData().toString();
}

QString MainWindow::defaultWorkerPath() const
{
#if defined(Q_OS_WIN)
    return QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("NFSLAN.exe"));
#else
    return QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("NFSLAN.exe"));
#endif
}

QString MainWindow::defaultServerDirectory() const
{
    return QDir::currentPath();
}

QString MainWindow::selectedServerDirectory() const
{
    return serverDirectoryEdit_->text().trimmed();
}

QString MainWindow::selectedWorkerBinary() const
{
    return workerBinaryEdit_->text().trimmed();
}

bool MainWindow::validateStartInputs(QString* errorMessage) const
{
    const QString serverName = serverNameEdit_->text().trimmed();
    if (serverName.isEmpty())
    {
        *errorMessage = QStringLiteral("Server name cannot be empty.");
        return false;
    }

    const QString serverDirectory = selectedServerDirectory();
    if (serverDirectory.isEmpty() || !QDir(serverDirectory).exists())
    {
        *errorMessage = QStringLiteral("Server directory does not exist.");
        return false;
    }

#if !defined(Q_OS_WIN) || !defined(NFSLAN_WINDOWS_EMBED_WORKER)
    const QString workerBinary = selectedWorkerBinary();
    const QFileInfo workerInfo(workerBinary);
    if (workerBinary.isEmpty() || !workerInfo.exists() || !workerInfo.isFile())
    {
        *errorMessage = QStringLiteral("Worker executable path is invalid.");
        return false;
    }
#endif

    const QFileInfo serverDll(QDir(serverDirectory).filePath(QStringLiteral("server.dll")));
    if (!serverDll.exists())
    {
        *errorMessage = QStringLiteral("server.dll was not found in the selected server directory.");
        return false;
    }

#if !defined(Q_OS_WIN)
    const QStringList runtimeCommand = normalizedRuntimeCommand(wineBinaryEdit_->text());
    const QString runtimeProgram = runtimeCommand.first();

    bool runtimeExecutableFound = false;
    const QFileInfo runtimeFileInfo(runtimeProgram);
    if (runtimeFileInfo.isAbsolute() || runtimeProgram.contains(QLatin1Char('/')))
    {
        runtimeExecutableFound = runtimeFileInfo.exists() && runtimeFileInfo.isFile();
    }
    else
    {
        runtimeExecutableFound = !QStandardPaths::findExecutable(runtimeProgram).isEmpty();
    }

    if (!runtimeExecutableFound)
    {
        *errorMessage = QStringLiteral("Runtime command executable was not found: %1").arg(runtimeProgram);
        return false;
    }
#endif

    return true;
}

void MainWindow::appendLogLine(const QString& line)
{
    const QString timestamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    logView_->append(QStringLiteral("[%1] %2").arg(timestamp, line));
}

void MainWindow::loadSettings()
{
    QSettings settings(QStringLiteral("NFSLAN"), QStringLiteral("NFSLAN-GUI"));

    restoreGeometry(settings.value(QStringLiteral("ui/geometry")).toByteArray());

    const int selectedGame = settings.value(QStringLiteral("ui/selectedGame"), 0).toInt();
    if (selectedGame >= 0 && selectedGame < gameCombo_->count())
    {
        gameCombo_->setCurrentIndex(selectedGame);
    }

#if defined(Q_OS_WIN) && defined(NFSLAN_WINDOWS_EMBED_WORKER)
    workerBinaryEdit_->setText(QStringLiteral("(embedded in this executable)"));
#else
    workerBinaryEdit_->setText(
        settings.value(QStringLiteral("worker/path"), defaultWorkerPath()).toString());
#endif

#if !defined(Q_OS_WIN)
    wineBinaryEdit_->setText(
        settings
            .value(
                QStringLiteral("worker/runtimeCommand"),
                settings.value(QStringLiteral("worker/wineBinary"), QStringLiteral("wine")))
            .toString());
#endif

    disablePatchingCheck_->setChecked(settings.value(QStringLiteral("worker/disablePatching"), false).toBool());
    clearLogOnStartCheck_->setChecked(settings.value(QStringLiteral("ui/clearLogOnStart"), false).toBool());

    activeProfileKey_ = currentProfileKey();
    loadProfile(activeProfileKey_);
}

void MainWindow::saveSettings()
{
    QSettings settings(QStringLiteral("NFSLAN"), QStringLiteral("NFSLAN-GUI"));

    settings.setValue(QStringLiteral("ui/geometry"), saveGeometry());
    settings.setValue(QStringLiteral("ui/selectedGame"), gameCombo_->currentIndex());
#if !defined(Q_OS_WIN) || !defined(NFSLAN_WINDOWS_EMBED_WORKER)
    settings.setValue(QStringLiteral("worker/path"), selectedWorkerBinary());
#endif
#if !defined(Q_OS_WIN)
    settings.setValue(QStringLiteral("worker/runtimeCommand"), wineBinaryEdit_->text().trimmed());
    settings.setValue(QStringLiteral("worker/wineBinary"), wineBinaryEdit_->text().trimmed());
#endif
    settings.setValue(QStringLiteral("worker/disablePatching"), disablePatchingCheck_->isChecked());
    settings.setValue(QStringLiteral("ui/clearLogOnStart"), clearLogOnStartCheck_->isChecked());

    saveProfile(currentProfileKey());
}

void MainWindow::loadProfile(const QString& profileKey)
{
    QSettings settings(QStringLiteral("NFSLAN"), QStringLiteral("NFSLAN-GUI"));
    const QString basePath = QStringLiteral("profiles/%1/").arg(profileKey);

    const QString defaultName = (profileKey == QStringLiteral("ug2"))
                                    ? QStringLiteral("UG2 Dedicated Server")
                                    : QStringLiteral("MW Dedicated Server");

    serverNameEdit_->setText(settings.value(basePath + QStringLiteral("serverName"), defaultName).toString());
    serverDirectoryEdit_->setText(
        settings.value(basePath + QStringLiteral("serverDirectory"), defaultServerDirectory()).toString());
}

void MainWindow::saveProfile(const QString& profileKey)
{
    QSettings settings(QStringLiteral("NFSLAN"), QStringLiteral("NFSLAN-GUI"));
    const QString basePath = QStringLiteral("profiles/%1/").arg(profileKey);

    settings.setValue(basePath + QStringLiteral("serverName"), serverNameEdit_->text().trimmed());
    settings.setValue(basePath + QStringLiteral("serverDirectory"), selectedServerDirectory());
}
