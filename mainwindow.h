#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QButtonGroup>

void formatString(QString &org, int n, const QChar &ch);

QByteArray hexStringtoByteArray(QString hex,int n);

QByteArray xorArithmetic(QByteArray srcData1,QByteArray srcData2);

QByteArray notArithmetic(QByteArray srcData);

QByteArray MY_DES_ecb_encrypt(QByteArray KEY, QByteArray srcData, int type);

QByteArray My_SM4_ecb_encrypt(QByteArray KEY,QByteArray srcData,int type);

QByteArray TDES_ECB_ENCRYPT_ASCII(QByteArray srcData,QByteArray KEY,int type);

QByteArray SM4_ECB_ENCRYPT_ASCII(QByteArray srcData,QByteArray KEY,int type);

QByteArray SM4_ECB_ENCRYPT_ASCII2(QByteArray srcData,QByteArray KEY,int type,int len = 16);

void byte_xor(unsigned char *desc,unsigned char *src,int len);

void String2Byte(int len, unsigned char *InBuf, unsigned char *OutBuf);

void Byte2String(int len, unsigned char *InBuf, unsigned char *OutBuf);

int GetHexLen(int length, unsigned char *Hex);

int getPinLength(unsigned char* pin);

void ABC_Get_3624PIN(unsigned char cryptFlag,
                     unsigned char *pan,
                     unsigned char *inPin,
                     unsigned int inPinLen,
                     unsigned char *outPin,
                     QByteArray key);

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_ECCButton_clicked();

    void on_EVEVButton_clicked();

    void on_srcTextEdit_textChanged();

    void on_dstTextEdit_textChanged();

    void on_CVVPushButton_clicked();

    void on_PANLineEdit_textChanged(const QString &arg1);

    void on_CVKaTextEdit_textChanged();

    void on_CVKbTextEdit_textChanged();

    void on_CVVLineEdit_textChanged(const QString &arg1);

    void on_CVVCleanPushButton_clicked();

    void on_EXpushButton_clicked();

    void on_offsetPushButton_clicked();

    void on_offsetCleanPushButton_clicked();

    void on_sessionKeyPushButton_clicked();

    void on_KCIPushButton_clicked();

    void on_KCICleanPushButton_clicked();

    void on_LMKTextEdit_textChanged();

    void on_KCIKeyTextEdit_textChanged();

    void on_PVKTextEdit_textChanged();

    void on_decimalLineEdit_textChanged(const QString &arg1);

    void on_validationLineEdit_textChanged(const QString &arg1);

    void on_sessionKeyCleanPushButton_clicked();

    void on_BDKTextEdit_textChanged();

    void on_KSNLineEdit_textChanged(const QString &arg1);

    void on_sesKeyLineEdit_textChanged(const QString &arg1);

    void on_XKEYPushButton_clicked();

    void on_XCleanPushButton_clicked();

    void on_XLMKTextEdit_textChanged();

    void on_XSRCKEYTextEdit_textChanged();

    void on_XDSTKEYTextEdit_textChanged();


    void on_PPINPushButton_clicked();

    void on_PPinBlockPushButton_clicked();

private:
    Ui::MainWindow *ui;
    QButtonGroup* pButtonGroup;
    QButtonGroup* pButtonGroupX;
    QButtonGroup* pButtonGroupP;
    QButtonGroup* pButtonGroupP2;
};

#endif // MAINWINDOW_H
