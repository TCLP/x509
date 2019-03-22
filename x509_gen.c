#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openss/bn.h>
#include <openssl/txt.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <pkcs12.h>
#include <pkcs7.h>
#include <engine.h>
#include <memory.h>
#include <malloc.h>

#define RSA_BITS        2048
#define RSA_PASS        "sa"
#define RSA_PRI_PATH    "rsa.pri"
#define RSA_PUB_PATH    "rsa.pub"

#define X509_REQ_VERSION 1
#define X509_REQ_COMMONE_NAME "openssl"
#define X509_REQ_COUNTRY_NAME "xa"
#define X509_REQ_ORGANIZATION_NAME "mcarlo"
#define X509_REQ_ORGANIZATION_UNIT_NAME "mcarlo"
#define X509_REQ_CSR_PATH "certreq.csr"

#define X509_CERT_VERSION1 0
#define X509_CERT_VERSION2 1
#define X509_CERT_VERSION3 2
#define X509_SERIAL_NUMBER 3
#define X509_CERT_FILEPATH "ca.cer"

#define PKCS12_PASSPHRSE "sa"
#define PKCS12_PFX_FILEPATH "ca.pfx"

int generate_keys()
{
    OpenSSL_add_all_algorithms();
    RSA *r = NULL;
    int ret = 0;
    BIGNUM *bne = NULL
    BIO *b = NULL;
    const EVP_CIPHER *enc = NULL;

    bne = BN_new();
    ret = BN_set_word(bne, RSA_3);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, RSA_BITS, bne, NULL);
    if(ret != 1)
    {
        printf("RSA_generate_key_ex failed\n");
        return -1;
    }
    //pri.key pem
    enc = EVP_des_ede3_ofb();
    b = BIO_new_file(RSA_PRI_PATH, "w");
    //这里的最后一个参数是密码
    ret = PEM_write_bio_RSAPrivateKey(b, r, enc, NULL, 0, RSA_PASS);
    if(ret != 1)
    {
        printf("PEM_write_bio_RSAPrivateKey failed\n");
        BIO_free(b);
        RSA_free(r);
        return -1;
    }

    //pub.key pem
    BIO_flush(b);
    BIO_free(b);
    b = BIO_new_file(RSA_PUB_PATH, "w");
    ret = PEM_write_bio_RSAPublicKey(b, r);
    if(ret != 1)
    {
        printf("PEM_write_bio_RSAPublicKey failed...\n");
        BIO_free(b);
        RSA_free(r);
        return -1;
    }
}

//生成csr请求文件
int generate_csr(char *prikey_file)
{
    OpenSSL_add_all_algorithms();
    X509_REQ *req = NULL;
    int ret = 0;
    X509_NAME *name = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    X509_NAME_ENTRY *entry = NULL;
    char mdout[20];
    int mdlen;
    const EVP_MD *md = NULL;
    BIO *b = NULL;

    req = X509_REQ_new();
    //set version
    ret = X509_REQ_set_version(req, X509_REQ_VERSION);
    //set name
    name = X509_NAME_new();
    entry = X509_NAME_ENTRY_create_by_txt(&entry, "commonName", V_ASN1_UTF8STRING, X509_REQ_COMMON_NAME, strlen(X509_REQ_COMMON_NAME));
    X509_NAME_add_entry(name, entry, 0, -1);
    entry = X509_NAME_ENTRY_create_by_txt(&entry, "countryName", V_ASN1_UTF8STRING, X509_REQ_COUNTRY_NAME, strlen(X509_REQ_COUNTRY_NAME));
    X509_NAME_add_entry(name, entry, 1, -1);
    //subject name
    ret = X509_REQ_set_subject_name(req, name);
    //pub key
    pkey = EVP_PKEY_new();
    if((ret = get_pri_key(&rsa, prikey_file)) == -1)
    {
        printf("get_pri_key failed\n");
        return -1;
    }
    EVP_PKEY_assign_RSA(pkey, rsa);
    //set public key
    ret = X509_REQ_set_pubkey(req, pkey);
    //set attribute
    ret = X509_REQ_add1_attr_by_txt(req, "organizationName", V_ASN1_UTF8STRING, X509_REQ_ORGANIZATION_NAME, strlen(X509_REQ_ORGANIZATION_NAME));
    ret = X509_REQ_add1_attr_by_txt(req, "organizationUnitName", V_ASN1_UTF8STRING, X509_REQ_ORGANIZATION_UNIT_NAME, strlen(X509_REQ_ORGANIZATION_UNIT_NAME));
    md = EVP_sha1();
    //将X509_REQ用指定的散列算法type进行散列,结果在md中,len是结果的长度
    ret = X509_REQ_digest(req, md, mdout, &mdlen);
    //对X509_REQ中X509_REQ_INFO结构用pkey于md进行签名,并用算法标识与签名填充X509_REQ中的sig_alg与signature域
    ret = X509_REQ_sign(req, pkey, md);
    if(!ret)
    {
        printf("sign err\n");
        X509_REQ_free(req);
        return -1;
    }
    //写入文件PEM格式
    b = BIO_new_file(X509_REQ_CSR_PATH, "w");
    PEM_write_bio_X509_REQ(b, req);
    BIO_free(b);
    return 0;
}


//用自己的私钥给自己的公钥csr签名
int generate_cert(char *prikey_file, char *csr_file)
{
    OpenSSL_add_all_algorithms();
    X509 *cert = NULL;
    X509_REQ *req = NULL;
    X509_NAME *pName =NULL;
    EVP_PKEY *rsa_pri_evp = NULL;
    const EVP_MD *md = NULL;
    int ret = 0;
    char mdout[20];
    int mdlen;

    if((cert = X509_new()) == NULL)
    {
        printf("X509_new failed\n");
        return -1;
    }
    //设置版本号
    if((ret = X509_set_version(cert, X509_CERT_VERSION3)) != 1)
    {
        printf("X509_set_version failed\n");
        return -1;
    }
    //设置序列号
    if((ret = ASN1_INTEGER_set(X509_get_serialNumber(cert), X509_SERIAL_NUMBER)) != 1)
    {
        printf("ASN1_INTEGER_set failed\n");
        return -1;
    }
    //设置证书开始时间
    if(!X509_gmtime_adj(X509_get_notBefore(cert), 0))
    {
        printf("X509_get_notBefore failed\n");
        return -1;
    }
    //设置证书结束时间
    if(!X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24))
    {
        printf("X509_get_notAfter failed\n");
        return -1;
    }
    //从文件中得到csr文件
    if(get_csr_file(&req, csr_file) == -1)
    {
        printf("get_csr_file failed\n");
        return -1;
    }
    //设置请求csr
    if(!X509_set_subject_name(cert, X509_REQ_get_subject_name(req)))
    {
        printf("X509_set_subject_name failed\n");
        return -1;
    }
    //得到csr中的公钥,并为X509证书文件设置公钥
    EVP_PKEY *tmppubkey = X509_REQ_get_pubkey(req);
    if(!tmppubkey || !X509_set_pubkey(cert, tmppubkey))
    {
        EVP_PKEY_free(tmppubkey);
        priintf("X509_set_pubkey\n");
        return -1;
    }
    EVP_PKEY_free(tmppubkey);
    //设置issuer_name
    if((pName = X509_REQ_get_subject_name(req)) == NULL)
    {
        printf("X509_REQ_get_subject_name failed\n");
        return -1;
    }
    //
    if(!X509_set_issuer_name(cert, pName))
    {
        printf("X509_set_issuer_name\n");
        return -1;
    }
    //得到ca的私钥
    if(get_pri_key_evp(&rsa_pri_evp, prikey_file) == -1)
    {
        printf("get_pri_key_evp failed\n");
        return -1;
    }

    md = EVP_sha1();
    ret = X509_digest(req, md, mdout, &mdlen);
    X509_sign(cert, rsa_pri_evp, md);
    if(save_cert(cert, X509_CERT_FILEPATH) == -1)
    {
        printf("save_cert failed\n");
        return -1;
    }
    return 0;
}

//生成pfx文件
int generate_pfx(char *prikey_file, char *cer_file)
{
    int len = 0;
    PKCS12 *p12 = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;
    unsigned char *p = NULL;
    unsigned char *buf = NULL;
    
    OpenSSL_add_all_algorithms();
    //open cert
    if(get_cert_file(&cert, cer_file) == -1)
    {
        printf("get_cert_file failed\n");
        return -1;
    }
    //open private key
    if(get_pri_key_evp(&pkey, prikey_file) == -1)
    {
        printf("get_pri_key_evp failed\n");
        return -1;
    }
    
    p12 = PKCS12_create(PKCS12_PASSPHRSE, "friend name", pkey, cert, NULL, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And40BitRC2_CBC, PKCS12_DEFAULT_ITER, -1, KEY_EX);
    len = i2d_PKCS12(p12, &p);
    BIO *newb = BIO_new_file(PKCS12_PFX_FILEPATH, "w");
    BIO_write(newb, p, len);
    BIO_free(newb);
    return 0;
}

int get_pri_key(RSA **rsa, char *prikey_file)
{
    *rsa = RSA_new();
    BIO *b = BIO_new_file(prikey_file, "rb");
    if((*rsa=PEM_read_bio_RSAPrivateKey(b, rsa, NULL, RSA_PASS)) == NULL)
    {
        printf("*rsa is null\n");
        return -1;
    }
    if((*rsa)->d != NULL)
        return 0;
    else
    {
        printf("PEM_read_bio_RSAPrivateKey failed\n");
        return -1;
    }
}

//将私钥从文件中取出来赋值给EVP_PKEY对象
int get_pri_key_evp(EVP_PKEY **rsa_pri_evp, char *prikey_file)
{
    BIO *pbio = NULL;
    if((pbio=BIO_new_file(prikey_file, "r")) == NULL)
    {
        printf("BIO_new_file failed\n");
        return -1;
    }
    *rsa_pri_evp = PEM_read_bio_PrivateKey(pbio, NULL, 0, NULL);
    if(NULL == *rsa_pri_evp)
    {
        printf("PEM_read_bio_PrivateKey failed\n");
        BIO_free(pbio);
        return -1;
    }
    BIO_free(pbio);
}


//将csr从文件中读取出来
int get_csr_file(X509_REQ **req, char *csr_file)
{
    BIO *b = BIO_new_file(csr_file, "r");
    *req = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);
    if(*req == NULL)
    {
        printf("PEM_read_bio_X509_REQ failed\n");
        return -1;
    }
    return 0;
}


//将cert从文件中读取出来
int get_cert_file(X509 **cert, char *cer_file)
{
    BIO *bio;
    bio = BIO_new_file(cer_file, "r");
    if(NULL == bio)
    {
        printf("BIO_new_file failed\n");
        return -1;
    }
    if((*cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL)
    {
        printf("PEM_read_bio_X509 failed\n");
        return -1;
    }
    return 0;
}

//保存cert到文件
int save_cert(X509 *cert, char *filepath)
{
    BIO *pbio;
    if(NULL == pbio || NULL==filepath)
        return -1;
    pbio = BIO_new_file(filepath, "w");
    if(NULL == pbio)
        return -1;
    if(!PEM_write_bio_X509(pbio, cert))
    {
        printf("PEM_write_bio_X509 failed\n");
        return -1;
    }
    BIO_free(pbio);
    return 0;
}


int main(int argc, char *argv[])
{
    int c = 0;
    int opt = 0;
    static struct option long_options[]={
        {"gen_rsa", no_argument, NULL, 'a'},//生成公私钥文件
        {"gen_csr", no_argument, NULL, 'b'},//生成csr文件，需要私钥参数
        {"gen_cer", no_argument, NULL, 'c'},//生成cer文件，需要ca的私钥和csr文件
        {"gen_pfx", no_argument, NULL, 'd'},//生成pfx文件，需要客户自己cer文件和客户自己的私钥
        {"csr", required_argument, NULL, 'e'},//指定csr文件
        {"prikey", required_argument, NULL, 'f'},//指定私钥文件
        {"cer", required_argument, NULL, 'g'},//指定cer文件
        {0,0,0,0},
    };
    char prikey_file[100] = {0};
    char csr_file[100] = {0};
    char cer_file[100] = {0};
    while((c=getopt_long(argc, argv, "h", long_options, NULL)) != -1)
    {
        switch(c)
        {
            case 'a':
                opt += 1;
                break;
            case 'b':
                opt += 2;
                break;
            case 'c':
                opt += 3;
                break;
            case 'd':
                opt += 4;
                break;
            case 'e':
                opt += 5;
                strcpy(csr_file, optarg);
                break;
            case 'f':
                strcpy(prikey_file, optarg);
                opt += 6;
                break;
            case 'g':
                opt += 7;
                strcpy(cer_file, optarg);
                break;
            case 'h':
                printf("./demo --gen_rsa\n");
                printf("./demo --gen_csr --prikey rsa.pri\n");
                printf("./demo --gen_cer --prikey rsa.pri --csr x.csr\n");
                printf("./demo --gen_pfx --prikey rsa.pri --cer x.cert\n");
                break;
            case '?':
                printf("参数无法识别\n");
                break;
        }
    }
    if(opt == 1)//生成公私钥
    {
        generate_keys();
        printf("done\n");
    }
    else if(opt == 8)
    {
        generate_csr(prikey_file);
        printf("done\n");
    }
    else if(opt == 14)
    {
        generate_cert(prikey_file, csr_file);
        printf("done\n");
    }
    else if(opt == 17)
    {
        generate_pfx(prikey_file, cer_file);
        printf("done\n");
    }
    else
        printf("参数无法识别\n");
    return 0;
}