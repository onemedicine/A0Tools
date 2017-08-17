#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <QMessageBox>
#include <openssl/des.h>
#include <openssl/evp.h>
#include "sm4.h"
#include <QButtonGroup>
using namespace std;

void byte_xor(unsigned char *desc,unsigned char *src,int len)
{
    int i;
    for(i=0;i<len;i++)
        desc[i]^=src[i];

}

static int Table_ASC_HEX[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f333
};

void String2Byte(int len, unsigned char *InBuf, unsigned char *OutBuf)
{
    for(; len>0; len-=2, InBuf+=2)
    {
        (*OutBuf++) = (Table_ASC_HEX[(*InBuf)]<<4)|Table_ASC_HEX[*(InBuf+1)];
    }
}

static const char HexToAsc1[] = "0123456789ABCDEF";

void Byte2String(int len, unsigned char *InBuf, unsigned char *OutBuf)
{
    for(; len>0; len--)
    {
        (*OutBuf++) = HexToAsc1[((*InBuf)>>4)&0xf];
        (*OutBuf++) = HexToAsc1[(*InBuf++)&0xf];
    }
}


int GetHexLen(int length, unsigned char *Hex)
{
    int i, index;

    index = 0;
    for (i = 0; i < length; i++)
    {
        if ((Hex[i] >= '0') && (Hex[i] <= '9'))
            index = 16 * index + (Hex[i] - '0');
        else
        {
            if ((Hex[i] >= 'A') && (Hex[i] <= 'F'))
                index = 16 * index + (Hex[i] - 'A' + 10);
            else if ((Hex[i] >= 'a') && (Hex[i] <= 'f'))
                index = 16 * index + (Hex[i] - 'a' + 10);
            else
                return -1;
        }
    }

    return index;
}


int getPinLength(unsigned char* pin)
{
    unsigned char *p = pin;
    int len = 0;
    if (pin == NULL)
    {
        return -1;
    }
    else
    {
        while (1)
        {
            if (*p == 'F' || *p == 'f')
            {
                break;
            }
            if (len > 12)
            {
                return -1;
            }
            len++;
            p++;

        }
        if (len < 4)
        {
            return -1;
        }
    }
    return len;
}


void ABC_Get_3624PIN(unsigned char cryptFlag,
                     unsigned char *pan,
                     unsigned char *inPin,
                     unsigned int inPinLen,
                     unsigned char *outPin,
                     QByteArray key)
{
    char validation[8] = {0};
    memset(validation, 0x00, 8);
    memcpy(validation + 2, pan, 6);

    unsigned char decimal[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5' };
    unsigned char buff[16] = { 0 };
    unsigned char midData[16] = { 0 };

    int i = 0;


    QByteArray Qvalidation(validation,8);
    QByteArray QlocaKey;
    QlocaKey = MY_DES_ecb_encrypt(key,Qvalidation,DES_ENCRYPT);
    QByteArray Qbuff = QlocaKey.toHex().toUpper();

    //  qDebug("%s",Qbuff.data());

    memcpy(buff,Qbuff.constData(),16);

    for (i = 0; i < 16; i++)
    {
        int k;
        if (buff[i] >= 'A'){
            k = buff[i] - 'A' + 10;
        }
        else{
            k = buff[i] - '0';
        }
        midData[i] = decimal[k];
    }
    if(cryptFlag == 1)
    {
        for (i = 0; i < inPinLen; i++)
        {
            if (inPin[i] >= midData[i])
            {
                midData[i] = inPin[i] - midData[i] + '0';
            }
            else
            {
                midData[i] = (inPin[i] + 10) - midData[i] + '0';
            }
        }

        memcpy(outPin, midData, inPinLen);
        if (inPinLen < 13)
        {
            for (; inPinLen < 13; inPinLen++)
            {
                *(outPin + inPinLen) = 'F';
            }
        }
    }
    else if(cryptFlag == 0)
    {
        for (i = 0; i < inPinLen; i++)
        {
            int sum = (inPin[i] - '0') + (midData[i] - '0');
            if(sum < 10)
            {
                midData[i] = sum + '0';

            }
            else{
                midData[i] = sum - 10 + '0';
            }

        }
        memcpy(outPin, midData, inPinLen);
    }
    else
    {
        return;
    }

    return;
}



//将十六进制字串每字节中间加空格分隔
void formatString(QString &org, int n, const QChar &ch)
{
    int size= org.size();
    int space= qRound(size*1.0/n+0.5)-1;
    if(space<=0)
        return;
    for(int i=0,pos=n;i<space;++i,pos+=(n+1))
    {
        org.insert(pos,ch);
    }
}
//十六进制字符串转十六进制编码，n表示每n字符转一个16进制编码：n = 2, "ffad"→0xff,0xad
QByteArray hexStringtoByteArray(QString hex,int n)
{
    QByteArray ret;
    hex=hex.trimmed();

    formatString(hex,n,' ');

    QStringList sl=hex.split(" ");
    foreach(QString s,sl)
    {
        if(!s.isEmpty())
            ret.append((char)s.toInt(0,16)&0xFF);
    }
    return ret;
}
//字符串异或
QByteArray xorArithmetic(QByteArray srcData1,QByteArray srcData2)
{
    QByteArray dstData;
    srcData1 = hexStringtoByteArray(QString(srcData1),1);
    srcData2 = hexStringtoByteArray(QString(srcData2),1);
    int size = (srcData1.size() > srcData2.size())?(srcData1.size()):(srcData2.size());
    int i = 0;
    for(i = 0; i < size; i++)
    {
        dstData[i] = srcData1[i] ^ srcData2[i];
    }
    //十六进制编码转16进制字符0x0f/0xff → 'f'
    for(i = 0; i < size; i++)
    {
        dstData[i] = dstData[i] & 0x0f;
        int d = dstData[i];
        dstData[i] = (QString::number(d,16)).toLatin1().at(0);
    }
    return dstData;
}

QByteArray notArithmetic(QByteArray srcData)
{
    srcData = hexStringtoByteArray(QString(srcData),1);
    int size = srcData.size();
    QByteArray dstData;
    int i = 0 ;
    for(i = 0; i < size; i++)
    {
        dstData[i] = ~srcData[i];
    }
    //十六进制编码转16进制字符0x0f/0xff → 'f'
    for(i = 0; i < size; i++)
    {
        dstData[i] = dstData[i] & 0x0f;
        int d = dstData[i];
        dstData[i] = (QString::number(d,16)).toLatin1().at(0);
    }
    return dstData;
}

QByteArray MY_DES_ecb_encrypt(QByteArray KEY,QByteArray srcData,int type)
{
    if(KEY.isEmpty() || srcData.isEmpty())
    {
        return "";
    }
    int flag = KEY.size() / 16;
    QByteArray hexKEY = hexStringtoByteArray(KEY,2);

    QByteArray buff(8,'0');
    DES_cblock key1;
    DES_cblock key2;
    DES_cblock key3;
    DES_key_schedule  schedule1;
    DES_key_schedule  schedule2;
    DES_key_schedule  schedule3;

    if(flag >= 1){
        memcpy(&key1,hexKEY.mid(0,8).data(),8);
        DES_set_key(&key1,&schedule1);
    }
    if(flag >= 2){
        memcpy(&key2,hexKEY.mid(8,8).data(),8);
        DES_set_key(&key2,&schedule2);
        memcpy(&key3,hexKEY.mid(0,8).data(),8);
        DES_set_key(&key3,&schedule3);
    }
    if(flag == 3){
        memcpy(&key3,hexKEY.mid(16,8).data(),8);
        DES_set_key(&key3,&schedule3);
    }

    if(flag >= 2){
        if(type == DES_ENCRYPT){
            DES_ecb3_encrypt((const_DES_cblock*)srcData.data(),(DES_cblock*)buff.data(),
                             &schedule1,&schedule2,&schedule3,DES_ENCRYPT);
        }else{
            DES_ecb3_encrypt((const_DES_cblock*)srcData.data(),(DES_cblock*)buff.data(),
                             &schedule1,&schedule2,&schedule3,DES_DECRYPT);
        }
    }
    else {
        if(type == DES_ENCRYPT){
            DES_ecb_encrypt((const_DES_cblock*)srcData.data(),(DES_cblock*)buff.data(), &schedule1, DES_ENCRYPT);
        }
        else{
            DES_ecb_encrypt((const_DES_cblock*)srcData.data(),(DES_cblock*)buff.data(), &schedule1, DES_DECRYPT);
        }
    }
    return buff;
}

QByteArray My_SM4_ecb_encrypt(QByteArray KEY, QByteArray srcData, int type)
{
    if(KEY.isEmpty() || srcData.isEmpty())
    {
        return "";
    }
    sm4_context ctx;
    QByteArray hexKEY = hexStringtoByteArray(KEY,2);
    QByteArray buff(16,'0');
    //sm4 ecb加密
    if(type == SM4_ENCRYPT)
    {
        ctx.mode = SM4_ENCRYPT;
        sm4_setkey_enc(&ctx,(unsigned char*)hexKEY.data());
        sm4_crypt_ecb(&ctx,1,16,(unsigned char*)srcData.data(),(unsigned char*)buff.data());
    }
    else//解密
    {
        ctx.mode = SM4_DECRYPT;
        sm4_setkey_dec(&ctx,(unsigned char*)hexKEY.data());
        sm4_crypt_ecb(&ctx,0,16,(unsigned char*)srcData.data(),(unsigned char*)buff.data());
    }
    return buff;
}

QByteArray TDES_ECB_ENCRYPT_ASCII(QByteArray srcData,QByteArray KEY,int type)
{
    DES_cblock key1;
    DES_cblock key2;
    DES_cblock key3;

    DES_key_schedule  schedule1;
    DES_key_schedule  schedule2;
    DES_key_schedule  schedule3;
    QByteArray dstData;
    QByteArray outBuff(8,'0');
    int keyLength = KEY.size();
    int dataLength = srcData.size() / 8;
    if((srcData.size() % 8) != 0)
    {
        return dstData;
    }
    if(keyLength == 16)
    {
        memcpy(&key1,KEY.mid(0,8).data(),8);
        memcpy(&key2,KEY.mid(8,8).data(),8);
        memcpy(&key3,KEY.mid(0,8).data(),8);
    }
    else if(keyLength == 24)
    {
        memcpy(&key1,KEY.mid(0,8).data(),8);
        memcpy(&key2,KEY.mid(8,8).data(),8);
        memcpy(&key3,KEY.mid(16,8).data(),8);
    }
    else if(keyLength == 8)
    {
        memcpy(&key1,KEY.mid(0,8).data(),8);
    }
    else
    {
        return dstData;
    }

    //解密
    int j = 0;
    if(type == DES_DECRYPT)
    {
        if(keyLength > 8)
        {
            DES_set_key(&key1,&schedule1);
            DES_set_key(&key2,&schedule2);
            DES_set_key(&key3,&schedule3);
        }
        else
        {
            DES_set_key(&key1,&schedule1);
        }
        for(j = 0; j < dataLength ; j++)
        {
            if(keyLength == 8)
            {
                DES_ecb_encrypt((const_DES_cblock*)srcData.mid(j*8,8).data(),(DES_cblock*)outBuff.data(), &schedule1, DES_DECRYPT);
            }else
            {
                DES_ecb3_encrypt((const_DES_cblock*)srcData.mid(j*8,8).data(),(DES_cblock*)outBuff.data(),
                                 &schedule1,&schedule2,&schedule3,DES_DECRYPT);
            }
            dstData += outBuff;
        }
    }
    //加密
    else
    {
        if(keyLength > 8)
        {
            DES_set_key(&key1,&schedule1);
            DES_set_key(&key2,&schedule2);
            DES_set_key(&key3,&schedule3);
        }
        else
        {
            DES_set_key(&key1,&schedule1);
        }
        for(j = 0; j < dataLength ; j++)
        {
            if(keyLength == 8)
            {
                DES_ecb_encrypt((const_DES_cblock*)srcData.mid(j*8,8).data(),(DES_cblock*)outBuff.data(), &schedule1, DES_ENCRYPT);
            }else
            {
                DES_ecb3_encrypt((const_DES_cblock*)srcData.mid(j*8,8).data(),(DES_cblock*)outBuff.data(),
                                 &schedule1,&schedule2,&schedule3,DES_ENCRYPT);
            }
            dstData += outBuff;
        }
    }
    return dstData;
}

QByteArray SM4_ECB_ENCRYPT_ASCII(QByteArray srcData,QByteArray KEY,int type)
{
    if(KEY.isEmpty() || srcData.isEmpty())
    {
        return "";
    }
    sm4_context ctx;
    QByteArray buff(16,'0');
    //sm4 ecb加密
    if(type == SM4_ENCRYPT)
    {
        ctx.mode = SM4_ENCRYPT;
        sm4_setkey_enc(&ctx,(unsigned char*)KEY.data());
        sm4_crypt_ecb(&ctx,1,16,(unsigned char*)srcData.data(),(unsigned char*)buff.data());
    }
    else//解密
    {
        ctx.mode = SM4_DECRYPT;
        sm4_setkey_dec(&ctx,(unsigned char*)KEY.data());
        sm4_crypt_ecb(&ctx,0,16,(unsigned char*)srcData.data(),(unsigned char*)buff.data());
    }
    return buff;
}
QByteArray SM4_ECB_ENCRYPT_ASCII2(QByteArray srcData,QByteArray KEY,int type,int len)
{
    if(KEY.isEmpty() || srcData.isEmpty())
    {
        return "";
    }
    sm4_context ctx;
    QByteArray buff(len,'0');
    //sm4 ecb加密
    if(type == SM4_ENCRYPT)
    {
        ctx.mode = SM4_ENCRYPT;
        sm4_setkey_enc(&ctx,(unsigned char*)KEY.data());
        sm4_crypt_ecb(&ctx,1,len,(unsigned char*)srcData.data(),(unsigned char*)buff.data());
    }
    else//解密
    {
        ctx.mode = SM4_DECRYPT;
        sm4_setkey_dec(&ctx,(unsigned char*)KEY.data());
        sm4_crypt_ecb(&ctx,0,len,(unsigned char*)srcData.data(),(unsigned char*)buff.data());
    }
    return buff;
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Tools - HEX");
    this->setMaximumSize(426,320);
    this->setMinimumSize(426,320);
    ui->tabWidget->setTabText(0,"PARITY");
    ui->tabWidget->setTabText(1,"VISA CVV ");
    pButtonGroup = new QButtonGroup(this);
    pButtonGroup->addButton(ui->KCIDESCheckBox,1);
    pButtonGroup->addButton(ui->KCISM4CheckBox, 2);


    pButtonGroupX = new QButtonGroup(this);
    pButtonGroupX->addButton(ui->XDESCheckBox,1);
    pButtonGroupX->addButton(ui->XSM4CheckBox, 2);

    pButtonGroupP = new QButtonGroup(this);
    pButtonGroupP->addButton(ui->P1CheckBox,1);
    pButtonGroupP->addButton(ui->P2CheckBox, 2);
    pButtonGroupP->addButton(ui->P3CheckBox,3);
    pButtonGroupP->addButton(ui->P4CheckBox, 4);
    pButtonGroupP->addButton(ui->P5CheckBox,5);
    pButtonGroupP->addButton(ui->P7CheckBox, 6);
    pButtonGroupP->addButton(ui->P50CheckBox, 7);


    pButtonGroupP2 = new QButtonGroup(this);
    pButtonGroupP2->addButton(ui->PDESCheckBox,1);
    pButtonGroupP2->addButton(ui->PSM4CheckBox, 2);


    ui->PINLineEdit->setMaxLength(12);
    QRegExp regx("[0-9]+$");
    QValidator *validator = new QRegExpValidator(regx);
    ui->PINLineEdit->setValidator(validator);
    ui->offsetSM4CheckBox->setDisabled(true);
    ui->offsetDESCheckBox->setDisabled(true);

    ui->PPanLineEdit->setValidator(validator);
    ui->PPinLineEdit->setValidator(validator);
    ui->PPinLineEdit->setMaxLength(12);
    ui->PPanLineEdit->setMaxLength(19);

}

MainWindow::~MainWindow()
{
    delete ui;
    delete pButtonGroup;
    delete pButtonGroupX;
}

void MainWindow::on_ECCButton_clicked()
{
    QString srcData = ui->srcTextEdit->toPlainText();
    if((srcData.isEmpty()) || (srcData.size()%2 != 0))
    {
        QMessageBox::warning(this, "waring", "data error");
        return;
    }
    QByteArray buff = hexStringtoByteArray(srcData,2);
    int size = buff.size();
    QByteArray dstData;
    for(int i = 0; i < size;i++)
    {
        unsigned char b = buff[i];       // 待检测的数字
        bool parity = false;  //初始判断标记
        unsigned char v = b & 0xFE;//只检测前7位中1的个数，最后一位做校验位
        while (v)
        {
            parity = !parity;
            v = v & (v - 1);
        }
        //parity为真表示奇数个1时，校验位为0，反则为1
        if(parity)
        {
            int k = 0xFE;
            b &= k;
        }else {
            int k = 0xFF>>7;
            b |= k;
        }
        dstData += b;
    }
    ui->dstTextEdit->setText(dstData.toHex().toUpper());
}

void MainWindow::on_EVEVButton_clicked()
{

    QString srcData = ui->srcTextEdit->toPlainText();
    if((srcData.isEmpty()) || (srcData.size()%2 != 0))
    {
        QMessageBox::warning(this, "waring", "data error");
        return;
    }
    QByteArray buff = hexStringtoByteArray(srcData,2);
    int size = buff.size();
    QByteArray dstData;
    for(int i = 0; i < size;i++)
    {
        unsigned char b = buff[i];       // 待检测的数字
        bool parity = false;  //初始判断标记
        unsigned char v = b & 0xFE;
        while (v)
        {
            parity = !parity;
            v = v & (v - 1);
        }
        //parity为真表示奇数个1时，校验位为1，反则为0
        if(!parity)
        {
            int k = 0xFE;
            b &= k;
        }else {
            int k = 0xFF>>7;
            b |= k;
        }
        dstData += b;
    }
    ui->dstTextEdit->setText(dstData.toHex().toUpper());
}

void MainWindow::on_srcTextEdit_textChanged()
{
    QString srcData = ui->srcTextEdit->toPlainText();
    //    srcData = srcData.toUpper();
    //    ui->srcTextEdit->setText(srcData);
    ui->srcLabel->setText(QString::number(srcData.size(),10) + " 字符");
}

void MainWindow::on_dstTextEdit_textChanged()
{
    QString srcData = ui->dstTextEdit->toPlainText();
    ui->dstLabel->setText(QString::number(srcData.size(),10) + " 字符");
}

void MainWindow::on_CVVPushButton_clicked()
{
    QString PAN = ui->PANLineEdit->text();
    QString CVKa = ui->CVKaTextEdit->toPlainText();
    QString CVKb = ui->CVKbTextEdit->toPlainText();
    if((PAN.isEmpty()) || (PAN.size() < 19) || (PAN.size() > 26))
    {
        QMessageBox::warning(this, "waring", "PAN+ error");
        return;
    }
    if((CVKa.isEmpty()) || (CVKa.size()%8 != 0))
    {
        QMessageBox::warning(this, "waring", "CVKa error");
        return;
    }
    if((CVKb.isEmpty()) || (CVKb.size()%8 != 0))
    {
        QMessageBox::warning(this, "waring", "CVKb error");
        return;
    }
    int flag1 = CVKa.size() / 16;
    int flag2 = CVKb.size() / 16;
    QByteArray data1;
    QByteArray data2;
    QByteArray buff(8,'0');
    QByteArray hexCVKa = hexStringtoByteArray(CVKa,2);
    QByteArray hexCVKb = hexStringtoByteArray(CVKb,2);
    int i = PAN.size();
    for(; i < 32; i++)
    {
        PAN.append('0');
    }
    data1 = hexStringtoByteArray(PAN.mid(0,16),2);
    //data2 = hexStringtoByteArray(PAN.mid(16,16),2);
    data2 = PAN.mid(16).toLatin1();

    DES_cblock key1;
    DES_cblock key2;
    DES_cblock key3;
    DES_key_schedule  schedule1;
    DES_key_schedule  schedule2;
    DES_key_schedule  schedule3;

    DES_cblock key4;
    DES_cblock key5;
    DES_cblock key6;
    DES_key_schedule  schedule4;
    DES_key_schedule  schedule5;
    DES_key_schedule  schedule6;
    if(flag1 >= 1){
        memcpy(&key1,hexCVKa.mid(0,8).data(),8);
        DES_set_key(&key1,&schedule1);
    }
    if(flag1 >= 2){
        memcpy(&key2,hexCVKa.mid(8,8).data(),8);
        DES_set_key(&key2,&schedule2);
        memcpy(&key3,hexCVKa.mid(0,8).data(),8);
        DES_set_key(&key3,&schedule3);
    }
    if(flag1 == 3){
        memcpy(&key3,hexCVKa.mid(16,8).data(),8);
        DES_set_key(&key3,&schedule3);
    }

    if(flag2 >= 1){
        memcpy(&key4,hexCVKb.mid(0,8).data(),8);
        DES_set_key(&key4,&schedule4);
    }
    if(flag2 >= 2){
        memcpy(&key5,hexCVKb.mid(8,8).data(),8);
        DES_set_key(&key5,&schedule5);
        memcpy(&key6,hexCVKb.mid(0,8).data(),8);
        DES_set_key(&key6,&schedule6);
    }
    if(flag2 == 3){
        memcpy(&key6,hexCVKb.mid(16,8).data(),8);
        DES_set_key(&key6,&schedule6);
    }

    if(flag1 >= 2){
        DES_ecb3_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(),
                         &schedule1,&schedule2,&schedule3,DES_ENCRYPT);
    }
    else {
        DES_ecb_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(), &schedule1, DES_ENCRYPT);
    }

    data1 = xorArithmetic(buff.toHex(),data2);
    data1 = hexStringtoByteArray(QString(data1),2);

    if(flag1 >= 2){
        DES_ecb3_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(),
                         &schedule1,&schedule2,&schedule3,DES_ENCRYPT);
    }
    else {
        DES_ecb_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(), &schedule1, DES_ENCRYPT);
    }

    data1 = buff;

    if(flag2 >= 2){
        DES_ecb3_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(),
                         &schedule4,&schedule5,&schedule6,DES_DECRYPT);
    }
    else {
        DES_ecb_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(), &schedule4, DES_DECRYPT);
    }

    data1 = buff;

    if(flag1 >= 2){
        DES_ecb3_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(),
                         &schedule1,&schedule2,&schedule3,DES_ENCRYPT);
    }
    else {
        DES_ecb_encrypt((const_DES_cblock*)data1.data(),(DES_cblock*)buff.data(), &schedule1, DES_ENCRYPT);
    }


    ui->CVVLineEdit->setText(QString(buff.toHex().toUpper()));
    buff = buff.toHex().toUpper();
    data1.clear();
    int size = buff.size();
    for(i = 0; i < size; i++)
    {
        if((buff[i] >= '0') && (buff[i] <= '9'))
        {
            data1.append(buff[i]);
        }
    }
    for(i = 0; i < size; i++)
    {
        if((buff[i] >= 'A') && (buff[i] <= 'F'))
        {
            data1.append(buff[i] - 'A' +'0');
        }
    }
    ui->CVVLineEdit_2->setText(QString(data1));
}

void MainWindow::on_PANLineEdit_textChanged(const QString &arg1)
{
    QString srcData = ui->PANLineEdit->text();
    ui->PANSizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_CVKaTextEdit_textChanged()
{
    QString srcData = ui->CVKaTextEdit->toPlainText();
    ui->CVKaSizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_CVKbTextEdit_textChanged()
{
    QString srcData = ui->CVKbTextEdit->toPlainText();
    ui->CVKbSizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_CVVLineEdit_textChanged(const QString &arg1)
{
    QString srcData = ui->CVVLineEdit->text();
    ui->CVVSizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_CVVCleanPushButton_clicked()
{
    ui->CVVLineEdit->clear();
    ui->CVVLineEdit_2->clear();
    ui->CVKbTextEdit->clear();
    ui->CVKaTextEdit->clear();
    ui->PANLineEdit->clear();
}

void MainWindow::on_EXpushButton_clicked()
{
    ui->PANLineEdit->setText("41234567890128701101");
    ui->CVKaTextEdit->setText("0123456789ABCDEF");
    ui->CVKbTextEdit->setText("FEDCBA9876543210");
}

void MainWindow::on_offsetPushButton_clicked()
{
    QString PVK = ui->PVKTextEdit->toPlainText();
    QString validation = ui->validationLineEdit->text();
    QString decimal = ui->decimalLineEdit->text();
    QString PIN = ui->PINLineEdit->text();
    //    if(ui->DESCheckBox->checkState() == Qt::Checked)
    //    {
    //        ui->PINLineEdit->setText("11111");
    //    }

    if((PVK.isEmpty()) || (PVK.size() % 8 != 0))
    {
        QMessageBox::warning(this, "waring", "PVK error");
        return ;
    }
    if(validation.size() != 16)
    {
        QMessageBox::warning(this, "waring", "validation error");
        return ;
    }
    if(decimal.size() != 16)
    {
        QMessageBox::warning(this, "waring", "decimal error");
        return ;
    }
    if(PIN.isEmpty())
    {
        QMessageBox::warning(this, "waring", "PIN error");
        return ;
    }
    int flag = PVK.size() / 16;
    QByteArray hexPVk = hexStringtoByteArray(PVK,2);
    QByteArray data = hexStringtoByteArray(validation,2);
    QByteArray buff(8,'0');
    DES_cblock key1;
    DES_cblock key2;
    DES_cblock key3;
    DES_key_schedule  schedule1;
    DES_key_schedule  schedule2;
    DES_key_schedule  schedule3;

    if(flag >= 1){
        memcpy(&key1,hexPVk.mid(0,8).data(),8);
        DES_set_key(&key1,&schedule1);
    }
    if(flag >= 2){
        memcpy(&key2,hexPVk.mid(8,8).data(),8);
        DES_set_key(&key2,&schedule2);
        memcpy(&key3,hexPVk.mid(0,8).data(),8);
        DES_set_key(&key3,&schedule3);
    }
    if(flag == 3){
        memcpy(&key3,hexPVk.mid(16,8).data(),8);
        DES_set_key(&key3,&schedule3);
    }

    if(flag >= 2){
        DES_ecb3_encrypt((const_DES_cblock*)data.data(),(DES_cblock*)buff.data(),
                         &schedule1,&schedule2,&schedule3,DES_ENCRYPT);
    }
    else {
        DES_ecb_encrypt((const_DES_cblock*)data.data(),(DES_cblock*)buff.data(), &schedule1, DES_ENCRYPT);
    }

    data = buff.toHex().toUpper();
    QString offset;
    for(int i = 0; i < 16; i++)
    {
        int k ;
        if(data[i] >= 'A'){
            k= data[i] - 'A' + 10;
        }else{
            k = data[i] - '0';
        }
        offset[i] = decimal[k];
    }

    int size = PIN.size();
    for(int i = 0; i < size; i++)
    {
        if(PIN[i] >= offset[i])
        {
            offset[i] = PIN[i].toLatin1() - offset[i].toLatin1() + '0';
        }
        else
        {
            offset[i] = (PIN[i].toLatin1() + 10 ) - offset[i].toLatin1() + '0';
        }
    }
    ui->offsetLineEdit->setText(offset.mid(0,PIN.size()));
}

void MainWindow::on_offsetCleanPushButton_clicked()
{
    ui->PVKTextEdit->clear();
    ui->validationLineEdit->clear();
    ui->decimalLineEdit->clear();
    ui->offsetLineEdit->clear();
    ui->PINLineEdit->clear();

}

void MainWindow::on_sessionKeyPushButton_clicked()
{
    QString BDK = ui->BDKTextEdit->toPlainText();
    QString KSN = ui->KSNLineEdit->text();
    if((BDK.size()%8 != 0) || (BDK.isEmpty()))
    {
        QMessageBox::warning(this, "waring", "BDK error");
        return ;
    }
    if(KSN.size() != 20)
    {
        QMessageBox::warning(this, "waring", "KSN error");
        return ;
    }
    QByteArray KSNR = hexStringtoByteArray(KSN.right(16),2);
    QByteArray KSNL = hexStringtoByteArray(KSN.left(16),2);
    KSNL[7] = KSNL[7] & 0xE0;

    QByteArray buff;
    QByteArray dataR(8,'0');
    QByteArray dataL(8,'0');
    QByteArray C0C0("C0C0C0C000000000");
    QByteArray FF("00000000000000FF");

    dataL = MY_DES_ecb_encrypt(BDK.toLatin1(),KSNL,DES_ENCRYPT);
    if(BDK.size() == 16)
    {
        buff = xorArithmetic(C0C0,BDK.toLatin1());
    }else if(BDK.size() == 32)
    {
        buff = xorArithmetic(C0C0 + C0C0,BDK.toLatin1());
    }else if(BDK.size() == 48)
    {
        buff = xorArithmetic(C0C0 + C0C0 + C0C0,BDK.toLatin1());
    }else
    {
        return;
    }

    dataR = MY_DES_ecb_encrypt(buff,KSNL,DES_ENCRYPT);

    QByteArray TC = KSN.right(6).toLatin1();
    QByteArray TCBuff(6,'0');
    TCBuff = hexStringtoByteArray(QString(TCBuff),2);

    TC = hexStringtoByteArray(QString(TC),2);
    int times = 0;
    unsigned char hex;

    for(int k = 0; k < 3; k++)
    {
        hex = TC[k];
        if(k != 0)
        {
            while(hex != 0){
                if((hex & 1) != 0)
                {
                    times++;
                }
                hex = (hex>>1);
            }
        }else
        {
            for ( int i=0;i<5;i++)
            {
                if ( hex & 0x0001 == 1) {
                    times ++;
                }
                hex = hex >> 1;
            }
        }
    }
    ui->sesKeyDispersalLineEdit->setText(QString::number(times,10));
    QByteArray keyR;
    QByteArray keyL;
    QByteArray KSNRBuff = KSNR.mid(0,5);

    if(times == 0)
    {
        ui->sesKeyLineEdit->setText(QString(dataL.toHex()+ dataR.toHex()).toUpper());
        return;
    }
    TCBuff[0] = TC[0] & 0xE0;
    for(int k = 0; k < 3; k++)
    {
        hex = TC[k];
        if(k != 0)
        {
            unsigned char n = 0x80;
            int m = 0;
            while(hex != 0)
            {
                if((hex & 1) != 0)
                {
                    // static unsigned char n = 0x80;
                    //unsigned char nn = 0x00;
                    for( ; m < 8; m++)
                    {
                        if((TC[k] & n) == n)
                        {
                            TCBuff[k] = TCBuff[k] | n;
                            n = n >> 1;
                            break;
                        }
                        n = n >> 1;
                    }

                    KSNRBuff.replace(5,3,TCBuff);
                    keyR = xorArithmetic(dataR.toHex(),KSNRBuff.toHex());
                    keyR = hexStringtoByteArray(QString(keyR),2);
                    keyR = MY_DES_ecb_encrypt(dataL.toHex(),keyR,DES_ENCRYPT);
                    keyR = xorArithmetic(keyR.toHex(),dataR.toHex());
                    keyR = hexStringtoByteArray(QString(keyR),2);

                    dataL = xorArithmetic(dataL.toHex(),C0C0);
                    dataL = hexStringtoByteArray(QString(dataL),2);
                    dataR = xorArithmetic(dataR.toHex(),C0C0);
                    dataR = hexStringtoByteArray(QString(dataR),2);

                    keyL = xorArithmetic(dataR.toHex(),KSNRBuff.toHex());
                    keyL = hexStringtoByteArray(QString(keyL),2);
                    keyL = MY_DES_ecb_encrypt(dataL.toHex(),keyL,DES_ENCRYPT);
                    keyL = xorArithmetic(keyL.toHex(),dataR.toHex());
                    keyL = hexStringtoByteArray(QString(keyL),2);

                    dataR = keyR;
                    dataL = keyL;
                }
                hex = (hex>>1);
            }
        }else
        {
            unsigned char n = 0x10;
            int m = 0;
            for ( int i=0;i<5;i++)
            {
                if ( hex & 0x0001 == 1)
                {
                    for(; m < 5; m++)
                    {
                        if((TC[k] & n) == n)
                        {
                            TCBuff[k] = TCBuff[k] | n;
                            n = n >> 1;
                            break;
                        }
                        n = n >> 1;
                    }

                    KSNRBuff.replace(5,3,TCBuff);
                    keyR = xorArithmetic(dataR.toHex(),KSNRBuff.toHex());
                    keyR = hexStringtoByteArray(QString(keyR),2);
                    keyR = MY_DES_ecb_encrypt(dataL.toHex(),keyR,DES_ENCRYPT);
                    keyR = xorArithmetic(keyR.toHex(),dataR.toHex());
                    keyR = hexStringtoByteArray(QString(keyR),2);

                    dataL = xorArithmetic(dataL.toHex(),C0C0);
                    dataL = hexStringtoByteArray(QString(dataL),2);
                    dataR = xorArithmetic(dataR.toHex(),C0C0);
                    dataR = hexStringtoByteArray(QString(dataR),2);

                    keyL = xorArithmetic(dataR.toHex(),KSNRBuff.toHex());
                    keyL = hexStringtoByteArray(QString(keyL),2);
                    keyL = MY_DES_ecb_encrypt(dataL.toHex(),keyL,DES_ENCRYPT);
                    keyL = xorArithmetic(keyL.toHex(),dataR.toHex());
                    keyL = hexStringtoByteArray(QString(keyL),2);

                    dataR = keyR;
                    dataL = keyL;
                }
                hex = hex >> 1;
            }
        }
    }
    ui->sesKeyLineEdit->setText(QString(dataL.toHex()+ dataR.toHex()).toUpper());
    QByteArray dataLBuff = xorArithmetic(FF,dataL.toHex());
    QByteArray dataRBuff = xorArithmetic(FF,dataR.toHex());
    ui->sesKeyLineEdit_2->setText(QString(dataLBuff + dataRBuff).toUpper());
}


void MainWindow::on_KCIPushButton_clicked()
{
    QByteArray LMK = ui->LMKTextEdit->toPlainText().toLatin1().toUpper();
    QByteArray KEY = ui->KCIKeyTextEdit->toPlainText().toLatin1().toUpper();
    QByteArray KCI = KEY.right(8).toUpper();
    QByteArray kci(32,'0');

    if((KEY.isEmpty()) || (KEY.size() % 8 != 0))
    {
        QMessageBox::warning(this, "waring", "KEY error");
        return ;
    }
    if((LMK.isEmpty()) )
    {
        QByteArray ret(16,'0');
        QByteArray buff(32,'0');
        ret = hexStringtoByteArray(QString(buff).toUpper(),2);
        if(ui->KCIDESCheckBox->checkState() == Qt::Checked)
        {
            ret = MY_DES_ecb_encrypt(KEY,ret,DES_ENCRYPT);
            kci = ret.toHex().toUpper();
        }
        else
        {
            ret = My_SM4_ecb_encrypt(KEY,ret,SM4_ENCRYPT);
            kci = ret.toHex().toUpper();
        }
        ui->KCILineEdit->setText(QString(kci));
        ui->checkKCILineEdit->setText("Just KCV");
        return ;
    }
    else if(LMK.size() % 8 != 0)
    {
        QMessageBox::warning(this, "waring", "LMK error");
        return ;
    }

    else{
        if(ui->KCIDESCheckBox->checkState() == Qt::Checked)
        {

            QByteArray V1 = KEY.mid(0,8).toHex();
            QByteArray V2 = KEY.mid(8,8).toHex();

            QByteArray V3 = QString(KEY.mid(16,16)).toLatin1();
            QByteArray V4 = QString(KEY.mid(32,16)).toLatin1();
            QByteArray V5 = QString(KEY.mid(48,16)).toLatin1();

            QByteArray ret(16,'0');

            QByteArray buff(16,'0');
            ret = xorArithmetic(V1,V2);
            buff = xorArithmetic(ret,V3);
            ret = xorArithmetic(buff,V4);
            buff = xorArithmetic(ret,V5);
            ret = hexStringtoByteArray(QString(buff).toUpper(),2);

            ret = MY_DES_ecb_encrypt(LMK,ret,DES_ENCRYPT);
            kci = ret.mid(0,4).toHex().toUpper();
        }
        else if(ui->KCISM4CheckBox->checkState() == Qt::Checked)
        {
            QByteArray V1 = KEY.mid(0,16).toHex();
            QByteArray V2 = QString(KEY.mid(16,32)).toLatin1();

            QByteArray ret(16,'0');
            QByteArray buff(16,'0');
            ret = xorArithmetic(V1,V2);
            int size = KEY.size();
            int i = 48;
            for(;i < size; i += 32)
            {
                if((size - i) < 32)
                {
                    break;
                }
                QByteArray V3 = QString(KEY.mid(i,32)).toLatin1();
                buff = xorArithmetic(ret,V3);
                ret = buff;
            }

            ret = hexStringtoByteArray(QString(ret).toUpper(),2);
            ret = My_SM4_ecb_encrypt(LMK,ret,SM4_ENCRYPT);
            kci = ret.mid(0,4).toHex().toUpper();
        }
        ui->KCILineEdit->setText(QString(kci));
        if(KCI == kci)
        {
            ui->checkKCILineEdit->setText("校验通过");
        }else
        {
            ui->checkKCILineEdit->setText("校验失败");
        }
    }

}



void MainWindow::on_KCICleanPushButton_clicked()
{
    ui->LMKTextEdit->clear();
    ui->KCIKeyTextEdit->clear();
    ui->KCILineEdit->clear();
    ui->checkKCILineEdit->clear();
}

void MainWindow::on_LMKTextEdit_textChanged()
{
    QString srcData = ui->LMKTextEdit->toPlainText();
    ui->KCILMKsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_KCIKeyTextEdit_textChanged()
{
    QString srcData = ui->KCIKeyTextEdit->toPlainText();
    ui->KCIKEYsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_PVKTextEdit_textChanged()
{
    QString srcData = ui->PVKTextEdit->toPlainText();
    ui->offsetPVKsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_decimalLineEdit_textChanged(const QString &arg1)
{
    QString srcData = ui->decimalLineEdit->text();
    ui->offsetDecimalsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_validationLineEdit_textChanged(const QString &arg1)
{
    QString srcData = ui->validationLineEdit->text();
    ui->offsetValidationsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_sessionKeyCleanPushButton_clicked()
{
    ui->sesKeyDispersalLineEdit->clear();
    ui->sesKeyLineEdit->clear();
    ui->BDKTextEdit->clear();
    ui->KSNLineEdit->clear();
}

void MainWindow::on_BDKTextEdit_textChanged()
{
    QString srcData = ui->BDKTextEdit->toPlainText();
    ui->SESBDKsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_KSNLineEdit_textChanged(const QString &arg1)
{
    QString srcData = ui->KSNLineEdit->text();
    ui->SESKSNsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_sesKeyLineEdit_textChanged(const QString &arg1)
{
    QString srcData = ui->sesKeyLineEdit->text();
    ui->SESKEYsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_XKEYPushButton_clicked()
{
    QString LMK = ui->XLMKTextEdit->toPlainText();
    QString srcKEY = ui->XSRCKEYTextEdit->toPlainText();
    if(LMK.isEmpty())
    {
        QMessageBox::warning(this, "waring", "LMK error");
        return;
    }
    //if(((srcKEY.size() != 72) && (srcKEY.size() != 56)))
    if(srcKEY.size() % 8 != 0)
    {
        QMessageBox::warning(this, "waring", "KEY error");
        return;
    }

    QByteArray hexLV = srcKEY.mid(0,16).toLatin1();
    QByteArray hexRV = notArithmetic(hexLV);
    QByteArray hexLMK = xorArithmetic(hexLV + hexRV,LMK.toLatin1());
    QByteArray dstKEY;
    hexLMK = hexStringtoByteArray(QString(hexLMK),2);
    if(ui->XDESCheckBox->checkState() == Qt::Checked)
    {
        int dataLen = 0;
        unsigned int L1 = srcKEY[2].toLatin1() - '0';
        unsigned int L2 = srcKEY[3].toLatin1() - '0';
        unsigned int LL  = (L1 * 10) + L2;
        switch (LL) {
        case 1:
            dataLen = 16;
            break;
        case 2:
            dataLen = 32;
            break;
        case 3:
            dataLen = 48;
            break;
        case 4:
            dataLen = 64;
            break;
        default:
            QMessageBox::warning(this, "waring", "KEY TYPE error");
            return ;
            break;
        }
        QByteArray key = hexStringtoByteArray(srcKEY.mid(16,dataLen),2);
        dstKEY = TDES_ECB_ENCRYPT_ASCII(key,hexLMK,DES_DECRYPT);
        //dstKEY = MY_DES_ecb_encrypt(hexLMK.toHex(),key,DES_DECRYPT);
    }
    else if(ui->XSM4CheckBox->checkState() == Qt::Checked)
    {
        int dataLen = 0;
        unsigned int L1 = srcKEY[2].toLatin1() - '0';
        unsigned int L2 = srcKEY[3].toLatin1() - '0';
        unsigned int LL  = (L1 * 10) + L2;
        switch (LL)
        {
        case 10:
            dataLen = 1024;
            break;
        case 11:
            dataLen = 1152;
            break;
        case 12:
            dataLen = 1280;
            break;
        case 13:
            dataLen = 1408;
            break;
        case 14:
            dataLen = 1536;
            break;
        case 15:
            dataLen = 1664;
            break;
        case 16:
            if(srcKEY[1] == '1')
            {
                dataLen = 1792;
            }else{
                dataLen = 128;
            }
            break;
        case 17:
            dataLen = 1920;
            break;
        case 20:
            dataLen = 2048;
            break;
            //        case 16:
            //            dataLen = 128;
            //            break;
        case 24:
            dataLen = 192;
            break;
        default:
            QMessageBox::warning(this, "waring", "KEY TYPE error");
            return ;
            break;
        }
        QByteArray key = hexStringtoByteArray(srcKEY.mid(16,dataLen),2);
        dstKEY = SM4_ECB_ENCRYPT_ASCII2(key,hexLMK,SM4_DECRYPT,dataLen/2);
    }

    ui->XDSTKEYTextEdit->setText(QString(dstKEY.toHex().toUpper()));
}

void MainWindow::on_XCleanPushButton_clicked()
{
    ui->XLMKTextEdit->clear();
    ui->XSRCKEYTextEdit->clear();
    ui->XDSTKEYTextEdit->clear();
}

void MainWindow::on_XLMKTextEdit_textChanged()
{
    QString srcData = ui->XLMKTextEdit->toPlainText();
    ui->XLMKsizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_XSRCKEYTextEdit_textChanged()
{
    QString srcData = ui->XSRCKEYTextEdit->toPlainText();
    ui->XsrcKeySizeLabel->setText(QString::number(srcData.size(),10));
}

void MainWindow::on_XDSTKEYTextEdit_textChanged()
{
    QString srcData = ui->XDSTKEYTextEdit->toPlainText();
    ui->XdstKeySizeLabel->setText(QString::number(srcData.size(),10));
}



void MainWindow::on_PPINPushButton_clicked()
{
    if(ui->P1CheckBox->checkState() != Qt::Checked && ui->PSM4CheckBox->checkState() == Qt::Checked)
    {
        QMessageBox::warning(this, "waring", "pinformat is in conflict with arithmetic");
        return;
    }

    QString panSrc = ui->PPanLineEdit->text();
    int panLen = panSrc.size();
    QString pinSrc = ui->PPinLineEdit->text();
    int pinLen = pinSrc.size();

    //qDebug("%s",qPrintable(panSrc));
    // qDebug("%s",qPrintable(pinSrc));
    QString key = ui->PKeyTextEdit->toPlainText();
    if (ui->P7CheckBox->checkState() != Qt::Checked)
    {
        if((panSrc.isEmpty()) || (panSrc.size() < 12))
        {
            QMessageBox::warning(this, "waring", "pan error");
            return;
        }
    }
    if((pinSrc.isEmpty()) || (pinSrc.size() > 12)|| (pinSrc.size() < 4))
    {
        QMessageBox::warning(this, "waring", "pin error");
        return;
    }
    if((key.isEmpty()) || (key.size()%8 != 0))
    {
        QMessageBox::warning(this, "waring", "key error");
        return;
    }


    QByteArray pan12;
    if(panLen != 12)
    {
        pan12 = panSrc.mid((panLen - 13),12).toLatin1();
    }
    else{
        pan12 = panSrc.mid(0,12).toLatin1();
    }
    unsigned char pan[13] = {0};
    unsigned char panBuff[13] = {0};
    memcpy(panBuff,panSrc.toLatin1().data(),12);

    unsigned char pin[12] = {0};
    memcpy(pin,pinSrc.toLatin1().data(),pinLen);

    unsigned char dstPan[16] = { 0 };
    unsigned char dstPinBlock[32] = { 0 };
    unsigned char buff[32] = { 0 };
    char pinBlock[32] = {0};
    int pinBlockLen = 0;
    int dstLen = 0;
    int i = 0;
    String2Byte(12,panBuff,pan);
    //  qDebug((const char *)pin);
    //  qDebug((const char *)panBuff);
    //   qDebug("%d",pinLen);
    //   qDebug("%d",panLen);
    int pinFormat = this->pButtonGroupP->checkedId();
    // qDebug("%d",pinFormat);
    switch (pinFormat)
    {
    case 1:
    {
        if (ui->PSM4CheckBox->checkState() == Qt::Checked)
        {
            memcpy(dstPan + 10, pan, 6);
            memcpy(dstPinBlock + 2, pin, pinLen);
            for (i = (pinLen + 2); i < 32; i++)
            {
                *(dstPinBlock + i) = 'F';
            }

            dstPinBlock[0] = '0';
            dstPinBlock[1] = pinLen <= 9 ? pinLen + '0' : pinLen - 10 + 'A';
            String2Byte(32, dstPinBlock, buff);

            dstLen = 16;
        }
        else
        {
            memcpy(dstPan + 2, pan, 6);
            memcpy(dstPinBlock + 2, pin, pinLen);
            for (i = (pinLen + 2); i < 16; i++)
            {
                *(dstPinBlock + i) = 'F';
            }

            dstPinBlock[0] = '0';
            dstPinBlock[1] = pinLen <= 9 ? pinLen + '0' : pinLen - 10 + 'A';
            String2Byte(16, dstPinBlock, buff);
            dstLen = 8;
        }

        byte_xor(buff, dstPan, dstLen);

        memcpy(pinBlock, buff, dstLen);
        pinBlockLen = dstLen;

    }
        break;
    case 2:
    {
        if(pinLen > 6)
        {
            QMessageBox::warning(this, "waring", "pin length error");
            return;
        }
        memcpy(dstPinBlock + 1, pin, pinLen);
        for (i = pinLen; i < 6; i++)
        {
            *(dstPinBlock + i + 1) = '0';
        }
        for (i = 7; i < 16; i++)
        {
            *(dstPinBlock + i) = 'F';
        }
        dstPinBlock[0] = pinLen + '0';
        String2Byte(16, dstPinBlock, buff);
        dstLen = 8;
        memcpy(pinBlock, buff, dstLen);
        pinBlockLen = dstLen;
    }

        break;
    case 3:
    {
        memcpy(dstPinBlock , pin, pinLen);
        for (i = pinLen; i < 16; i++)
        {
            *(dstPinBlock + i) = 'F';
        }
        String2Byte(16, dstPinBlock, buff);
        dstLen = 8;
        memcpy(pinBlock, buff, dstLen);
        pinBlockLen = dstLen;
    }
        break;
    case 4:
    {
        memcpy(dstPan + 2, pan, 6);
        memcpy(dstPinBlock + 2, pin, pinLen);
        for (i = (pinLen + 2); i < 16; i++)
        {
            *(dstPinBlock + i) = 'F';
        }
        dstPinBlock[0] = '0';
        dstPinBlock[1] = pinLen <= 9 ? pinLen + '0' : pinLen - 10 + 'A';
        String2Byte(16, dstPinBlock, buff);
        dstLen = 8;
        byte_xor(buff, dstPan, dstLen);
        memcpy(pinBlock, buff, dstLen);
        pinBlockLen = dstLen;
    }
        break;
    case 5:
    {
        memcpy(dstPinBlock + 1, pin, pinLen);
        for (i = (pinLen + 1); i < 16; i++)
        {
            *(dstPinBlock + i) = 'F';
        }
        dstPinBlock[0] = pinLen <= 9 ? pinLen + '0' : pinLen - 10 + 'A';
       // qDebug((const char *)dstPinBlock);
        String2Byte(16, dstPinBlock, buff);
        dstLen = 8;
        //byte_xor(buff, pan, dstLen);
        memcpy(pinBlock, buff, dstLen);
        pinBlockLen = dstLen;
    }
        break;
    case 6:
    {
        if (ui->PSM4CheckBox->checkState() == Qt::Checked)
        {
            memcpy(dstPan + 10, pan, 6);
            memcpy(dstPinBlock + 2, pin, pinLen);
            for (i = (pinLen + 2); i < 32; i++)
            {
                *(dstPinBlock + i) = 'F';
            }

            dstPinBlock[0] = '0';
            dstPinBlock[1] = pinLen <= 9 ? pinLen + '0' : pinLen - 10 + 'A';
            String2Byte(32, dstPinBlock, (unsigned char *)pinBlock);

            pinBlockLen = 16;
        }
        else
        {
            memcpy(dstPan + 2, pan, 6);
            memcpy(dstPinBlock + 2, pin, pinLen);
            for (i = (pinLen + 2); i < 16; i++)
            {
                *(dstPinBlock + i) = 'F';
            }

            dstPinBlock[0] = '0';
            dstPinBlock[1] = pinLen <= 9 ? pinLen + '0' : pinLen - 10 + 'A';
            String2Byte(16, dstPinBlock, (unsigned char *)pinBlock);
            pinBlockLen = 8;
        }
        break;
    }
    case 7:
    {

        ABC_Get_3624PIN(1,
                        pan,
                        pin,
                        pinLen,
                        (unsigned char *)pinBlock,
                        key.toLatin1());
        pinBlockLen = 13;
    }
        break;
    default:
        QMessageBox::warning(this, "waring", "pin format error");
        return;
    }


    QByteArray QdstKey = key.toLatin1();
    QByteArray QpinBlock = QByteArray(pinBlock,pinBlockLen);
    //qDebug(QpinBlock.toHex().constData());
    QByteArray outData;
    if(pinFormat != 7)
    {
        if (ui->PSM4CheckBox->checkState() == Qt::Checked)
        {
            outData = My_SM4_ecb_encrypt(QdstKey,QpinBlock,SM4_ENCRYPT);
        }
        else
        {
            outData = MY_DES_ecb_encrypt(QdstKey,QpinBlock,DES_ENCRYPT);
        }

        ui->PPinBlockLineEdit->setText(outData.toHex().toUpper());
    }
    else{
        ui->PPinBlockLineEdit->setText(QString(pinBlock).toUpper());
    }


    return;

}

void MainWindow::on_PPinBlockPushButton_clicked()
{
    if(ui->P1CheckBox->checkState() != Qt::Checked && ui->PSM4CheckBox->checkState() == Qt::Checked)
    {
        QMessageBox::warning(this, "waring", "pinformat is in conflict with arithmetic");
        return;
    }

    QString panSrc = ui->PPanLineEdit->text();
    int panLen = panSrc.size();
    QString pinBlockSrc = ui->PPinBlockLineEdit->text();
    int pinBlockLen = pinBlockSrc.size();


    QString key = ui->PKeyTextEdit->toPlainText();
    if (ui->P7CheckBox->checkState() != Qt::Checked)
    {
        if(panSrc.isEmpty())
        {
            QMessageBox::warning(this, "waring", "pan error");
            return;
        }
    }

    if((pinBlockSrc.isEmpty()))
    {
        QMessageBox::warning(this, "waring", "pinBlock error");
        return;
    }
    if((key.isEmpty()) || (key.size()%8 != 0))
    {
        QMessageBox::warning(this, "waring", "key error");
        return;
    }

    QByteArray pan12;
    if(panLen != 12)
    {
        pan12 = panSrc.mid((panLen - 13),12).toLatin1();
    }
    else{
        pan12 = panSrc.mid(0,12).toLatin1();
    }
    unsigned char pan[16] = {0};
    unsigned char panBuff[13] = {0};
    unsigned char panBuff2[6] = {0};
    memcpy(panBuff,panSrc.toLatin1().data(),12);

    memset(pan, 0x00, sizeof(pan));
    String2Byte(12,panBuff,panBuff2);
    if (ui->P50CheckBox->checkState() != Qt::Checked)
    {
        if (ui->PDESCheckBox->checkState() == Qt::Checked)
        {
            memcpy(pan + 2, panBuff2, 6);
        }
        else
        {
            memcpy(pan + 10, panBuff2, 6);
        }
    }
    else
    {
        memcpy(pan, panBuff2, 6);
    }


  //  qDebug((const char *)panBuff);


    unsigned char inPinBlock[32] = {0};
    char outPin[13] = {0};
    unsigned int outPinLen = 0;

    unsigned char pinBlock[32] = {0};


    QByteArray QdstKey = key.toLatin1();
    QByteArray QpinBlock = hexStringtoByteArray(pinBlockSrc,2);
    QByteArray outData;
  //  qDebug("inpinBlock:%s",QpinBlock.toHex().data());
    int pinFormat = this->pButtonGroupP->checkedId();
   //qDebug("pinFormat:%d",pinFormat);
    if(pinFormat != 7)
    {
        if (ui->PSM4CheckBox->checkState() == Qt::Checked)
        {
            outData = My_SM4_ecb_encrypt(QdstKey,QpinBlock,SM4_DECRYPT);
        }
        else
        {
            outData = MY_DES_ecb_encrypt(QdstKey,QpinBlock,DES_DECRYPT);
        }

        memcpy(inPinBlock,outData.data(),outData.size());
        pinBlockLen = outData.size();
       // qDebug("pinblock:%s",outData.toHex().data());
    }
    else {
        memcpy(inPinBlock,pinBlockSrc.toLatin1().data(),pinBlockSrc.size());
        pinBlockLen = pinBlockSrc.size();
    }

    switch (pinFormat)
    {
    case 1:
    {
        unsigned char pin[16] = { 0 };
        memcpy(pin, inPinBlock, pinBlockLen);
        byte_xor(pin, pan, pinBlockLen);
        Byte2String(pinBlockLen, pin, pinBlock);
        int len = GetHexLen(2, pinBlock);
        if (len < 0)
        {
             QMessageBox::warning(this, "waring", "pinBlock error");
            return;
        }
        memcpy(outPin, pinBlock + 2, len);
        outPinLen = len;
    }
        break;
    case 2:
    {
        Byte2String(8, inPinBlock, pinBlock);
        int len = GetHexLen(1, pinBlock);
        if (len < 0)
        {
            QMessageBox::warning(this, "waring", "pinBlock error");
            return ;
        }
        memcpy(outPin, pinBlock + 1, len);
        outPinLen = len;
    }
        break;
    case 3:
    {
        Byte2String(8, inPinBlock, pinBlock);
        int len = getPinLength(pinBlock);
        if ( len < 0)
        {
            QMessageBox::warning(this, "waring", "pinBlock error");
            return ;
        }
        memcpy(outPin, pinBlock, len);
        outPinLen = len;
    }
        break;
    case 4:
    {
        unsigned char pin[16] = { 0 };
        memcpy(pin, inPinBlock, pinBlockLen);
        byte_xor(pin, pan, pinBlockLen);
        Byte2String(pinBlockLen, pin, pinBlock);
        int len = GetHexLen(2, pinBlock);
        if (len < 0)
        {
            QMessageBox::warning(this, "waring", "pinBlock error");
            return;
        }
        memcpy(outPin, pinBlock + 2, len);
        outPinLen = len;
    }
        break;
    case 5:
    {
        Byte2String(8, inPinBlock, pinBlock);
        int len = GetHexLen(1,pinBlock);
        if (len < 0)
        {
            QMessageBox::warning(this, "waring", "pinBlock error");
            return ;
        }
        memcpy(outPin, pinBlock + 1, len);
        outPinLen = len;
    }
        break;
    case 6:
    {
        Byte2String(pinBlockLen, inPinBlock, pinBlock);
        int len = GetHexLen(2, pinBlock);
        if (len < 0)
        {
            QMessageBox::warning(this, "waring", "pinBlock error");
            return ;
        }
        memcpy(outPin, pinBlock + 2, len);
        outPinLen = len;
    }
        break;
    case 7:
    {
        int len = getPinLength(inPinBlock);
        if (len < 0)
        {
            len = pinBlockLen;
        }
        ABC_Get_3624PIN(0,
                        pan,
                        inPinBlock,
                        len,
                        (unsigned char *)outPin,
                        key.toLatin1());
        outPinLen = len;
    }
        break;
    default:
        QMessageBox::warning(this, "waring", "pinformat error");
        return;
    }

    ui->PPinLineEdit->setText(QString(outPin));

    return ;
}
