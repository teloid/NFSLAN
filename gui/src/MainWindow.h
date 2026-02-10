#pragma once

#include <QMainWindow>
#include <QProcess>
#include <QString>

class QCheckBox;
class QComboBox;
class QLineEdit;
class QLabel;
class QPushButton;
class QTextEdit;
class QCloseEvent;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow();
    ~MainWindow() override = default;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void startServer();
    void stopServer();
    void browseServerDirectory();
    void browseWorkerBinary();
    void updateUiState();
    void readProcessOutput();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onGameProfileChanged(int index);

private:
    QString currentProfileKey() const;
    QString defaultWorkerPath() const;
    QString defaultServerDirectory() const;
    QString selectedServerDirectory() const;
    QString selectedWorkerBinary() const;
    bool validateStartInputs(QString* errorMessage) const;
    void appendLogLine(const QString& line);
    void loadSettings();
    void saveSettings();
    void loadProfile(const QString& profileKey);
    void saveProfile(const QString& profileKey);

    QString activeProfileKey_;
    QProcess* process_;
    QComboBox* gameCombo_;
    QLineEdit* serverNameEdit_;
    QLineEdit* serverDirectoryEdit_;
    QLineEdit* workerBinaryEdit_;
    QLineEdit* wineBinaryEdit_;
    QPushButton* startButton_;
    QPushButton* stopButton_;
    QTextEdit* logView_;
    QLabel* statusLabel_;
    QCheckBox* disablePatchingCheck_;
    QCheckBox* clearLogOnStartCheck_;
};
