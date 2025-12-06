#include "elf_util.h"
#include "elf32_pheader.h"
#include "elf64_pheader.h"
#include "util.h"
#include <string.h>

int verify_magic(const uint8_t *magic, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    if(magic[0] == ELFMAG0 && magic[1] == ELFMAG1 && magic[2] == ELFMAG2 && magic[3] == ELFMAG3)
    {
        strcpy(msg, "0x7FELF");
        ret_val = 0;
    }
    else
    {
        strcpy(msg, "INVALID ELFMAGIC");
        ret_val = -1;
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_class(const uint64_t class, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    switch(class)
    {
        case ELFCLASSNONE:
            strcpy(msg, "ELFCLASSNONE");
            ret_val = -1;
            break;
        case ELFCLASS64:
            strcpy(msg, "ELFCLASS64");
            ret_val = 0;
            break;
        case ELFCLASS32:
            strcpy(msg, "ELFCLASS32");
            ret_val = 0;
            break;
        default:
            strcpy(msg, "INVALID ELFCLASS");
            ret_val = -1;
            break;
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_data(const uint64_t data, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    switch(data)
    {
        case ELFDATANONE:
            strcpy(msg, "ELFDATANONE");
            ret_val = -1;
            break;
        case ELFDATA2MSB:
            strcpy(msg, "ELFDATA2MSB");
            ret_val = 0;
            break;
        case ELFDATA2LSB:
            strcpy(msg, "ELFDATA2LSB");
            ret_val = 0;
            break;
        default:
            strcpy(msg, "INVALID ELFDATA");
            ret_val = -1;
            break;
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_version(const uint64_t version, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    switch(version)
    {
        case EV_NONE:
            strcpy(msg, "EV_NONE");
            ret_val = -1;
            break;
        case EV_CURRENT:
            strcpy(msg, "EV_CURRENT");
            ret_val = 0;
            break;
        default:
            strcpy(msg, "INVALID ELFVERSION");
            ret_val = -1;
            break;
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_osabi(const uint64_t osabi, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    if(osabi >= OSABI_CUSTOM_BOTTOM && osabi <= OSABI_CUSTOM_TOP)
    {
        strcpy(msg, "Architecture specific ELFOSABI");
        ret_val = 0;
    }
    else
    {
        switch(osabi)
        {
            case ELFOSABI_NONE:
                strcpy(msg, "ELFOSABI_NONE");
                ret_val = 0;
                break;
            case ELFOSABI_HPUX:
                strcpy(msg, "ELFOSABI_HPUX");
                ret_val = 0;
                break;
            case ELFOSABI_NETBSD:
                strcpy(msg, "ELFOSABI_NETBSD");
                ret_val = 0;
                break;
            case ELFOSABI_GNU:
                strcpy(msg, "ELFOSABI_GNU");
                ret_val = 0;
                break;
            case ELFOSABI_SOLARIS:
                strcpy(msg, "ELFOSABI_SOLARIS");
                ret_val = 0;
                break;
            case ELFOSABI_AIX:
                strcpy(msg, "ELFOSABI_AIX");
                ret_val = 0;
                break;
            case ELFOSABI_IRIX:
                strcpy(msg, "ELFOSABI_IRIX");
                ret_val = 0;
                break;
            case ELFOSABI_FREEBSD:
                strcpy(msg, "ELFOSABI_FREEBSD");
                ret_val = 0;
                break;
            case ELFOSABI_TRU64:
                strcpy(msg, "ELFOSABI_TRU64");
                ret_val = 0;
                break;
            case ELFOSABI_MODESTO:
                strcpy(msg, "ELFOSABI_MODESTO");
                ret_val = 0;
                break;
            case ELFOSABI_OPENBSD:
                strcpy(msg, "ELFOSABI_OPENBSD");
                ret_val = 0;
                break;
            case ELFOSABI_OPENVMS:
                strcpy(msg, "ELFOSABI_OPENVMS");
                ret_val = 0;
                break;
            case ELFOSABI_NSK:
                strcpy(msg, "ELFOSABI_NSK");
                ret_val = 0;
                break;
            case ELFOSABI_AROS:
                strcpy(msg, "ELFOSABI_AROS");
                ret_val = 0;
                break;
            case ELFOSABI_FENIXOS:
                strcpy(msg, "ELFOSABI_FENIXOS");
                ret_val = 0;
                break;
            case ELFOSABI_CLOUDABI:
                strcpy(msg, "ELFOSABI_CLOUDABI");
                ret_val = 0;
                break;
            case ELFOSABI_OPENVOS:
                strcpy(msg, "ELFOSABI_OPENVOS");
                ret_val = 0;
                break;
            default:
                strcpy(msg, "UKNOWN ELFOSABI");
                ret_val = 0;
                break;
        }
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_type(const uint64_t type, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    if(type >= ET_LOOS && type <= ET_HIOS)
    {
        strcpy(msg, "OS specific ELFTYPE");
        ret_val = 0;
    }
    else if(type >= ET_LOPROC && type <= ET_HIPROC)
    {
        strcpy(msg, "Processor specific ELFTYPE");
        ret_val = 0;
    }
    else
    {
        switch(type)
        {
            case ET_NONE:
                strcpy(msg, "ET_NONE");
                ret_val = 0;
                break;
            case ET_CORE:
                strcpy(msg, "ET_CORE");
                ret_val = 0;
                break;
            case ET_DYN:
                strcpy(msg, "ET_DYN");
                ret_val = 0;
                break;
            case ET_EXEC:
                strcpy(msg, "ET_EXEC");
                ret_val = 0;
                break;
            case ET_REL:
                strcpy(msg, "ET_REL");
                ret_val = 0;
                break;
            default:
                strcpy(msg, "INVALID ELFTYPE");
                ret_val = -1;
                break;
        }
    }
    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_machine(const uint64_t machine, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    switch(machine)
    {
        case EM_NONE:
            strcpy(msg, "EM_NONE");
            ret_val = 0;
            break;
        case EM_M32:
            strcpy(msg, "EM_M32");
            ret_val = 0;
            break;
        case EM_SPARC:
            strcpy(msg, "EM_SPARC");
            ret_val = 0;
            break;
        case EM_386:
            strcpy(msg, "EM_386");
            ret_val = 0;
            break;
        case EM_68K:
            strcpy(msg, "EM_68K");
            ret_val = 0;
            break;
        case EM_88K:
            strcpy(msg, "EM_88K");
            ret_val = 0;
            break;
        case EM_IAMCU:
            strcpy(msg, "EM_IAMCU");
            ret_val = 0;
            break;
        case EM_860:
            strcpy(msg, "EM_860");
            ret_val = 0;
            break;
        case EM_MIPS:
            strcpy(msg, "EM_MIPS");
            ret_val = 0;
            break;
        case EM_S370:
            strcpy(msg, "EM_S370");
            ret_val = 0;
            break;
        case EM_MIPS_RS3_LE:
            strcpy(msg, "EM_MIPS_RS3_LE");
            ret_val = 0;
            break;
        case EM_PARISC:
            strcpy(msg, "EM_PARISC");
            ret_val = 0;
            break;
        case reserved:
            strcpy(msg, "reserved");
            ret_val = 0;
            break;
        case EM_VPP500:
            strcpy(msg, "EM_VPP500");
            ret_val = 0;
            break;
        case EM_SPARC32PLUS:
            strcpy(msg, "EM_SPARC32PLUS");
            ret_val = 0;
            break;
        case EM_960:
            strcpy(msg, "EM_960");
            ret_val = 0;
            break;
        case EM_PPC:
            strcpy(msg, "EM_PPC");
            ret_val = 0;
            break;
        case EM_PPC64:
            strcpy(msg, "EM_PPC64");
            ret_val = 0;
            break;
        case EM_S390:
            strcpy(msg, "EM_S390");
            ret_val = 0;
            break;
        case EM_SPU:
            strcpy(msg, "EM_SPU");
            ret_val = 0;
            break;
        case EM_V800:
            strcpy(msg, "EM_V800");
            ret_val = 0;
            break;
        case EM_FR20:
            strcpy(msg, "EM_FR20");
            ret_val = 0;
            break;
        case EM_RH32:
            strcpy(msg, "EM_RH32");
            ret_val = 0;
            break;
        case EM_RCE:
            strcpy(msg, "EM_RCE");
            ret_val = 0;
            break;
        case EM_ARM:
            strcpy(msg, "EM_ARM");
            ret_val = 0;
            break;
        case EM_ALPHA:
            strcpy(msg, "EM_ALPHA");
            ret_val = 0;
            break;
        case EM_SH:
            strcpy(msg, "EM_SH");
            ret_val = 0;
            break;
        case EM_SPARCV9:
            strcpy(msg, "EM_SPARCV9");
            ret_val = 0;
            break;
        case EM_TRICORE:
            strcpy(msg, "EM_TRICORE");
            ret_val = 0;
            break;
        case EM_ARC:
            strcpy(msg, "EM_ARC");
            ret_val = 0;
            break;
        case EM_H8_300:
            strcpy(msg, "EM_H8_300");
            ret_val = 0;
            break;
        case EM_H8_300H:
            strcpy(msg, "EM_H8_300H");
            ret_val = 0;
            break;
        case EM_H8S:
            strcpy(msg, "EM_H8S");
            ret_val = 0;
            break;
        case EM_H8_500:
            strcpy(msg, "EM_H8_500");
            ret_val = 0;
            break;
        case EM_IA_64:
            strcpy(msg, "EM_IA_64");
            ret_val = 0;
            break;
        case EM_MIPS_X:
            strcpy(msg, "EM_MIPS_X");
            ret_val = 0;
            break;
        case EM_COLDFIRE:
            strcpy(msg, "EM_COLDFIRE");
            ret_val = 0;
            break;
        case EM_68HC12:
            strcpy(msg, "EM_68HC12");
            ret_val = 0;
            break;
        case EM_MMA:
            strcpy(msg, "EM_MMA");
            ret_val = 0;
            break;
        case EM_PCP:
            strcpy(msg, "EM_PCP");
            ret_val = 0;
            break;
        case EM_NCPU:
            strcpy(msg, "EM_NCPU");
            ret_val = 0;
            break;
        case EM_NDR1:
            strcpy(msg, "EM_NDR1");
            ret_val = 0;
            break;
        case EM_STARCORE:
            strcpy(msg, "EM_STARCORE");
            ret_val = 0;
            break;
        case EM_ME16:
            strcpy(msg, "EM_ME16");
            ret_val = 0;
            break;
        case EM_ST100:
            strcpy(msg, "EM_ST100");
            ret_val = 0;
            break;
        case EM_TINYJ:
            strcpy(msg, "EM_TINYJ");
            ret_val = 0;
            break;
        case EM_X86_64:
            strcpy(msg, "EM_X86_64");
            ret_val = 0;
            break;
        case EM_PDSP:
            strcpy(msg, "EM_PDSP");
            ret_val = 0;
            break;
        case EM_PDP10:
            strcpy(msg, "EM_PDP10");
            ret_val = 0;
            break;
        case EM_PDP11:
            strcpy(msg, "EM_PDP11");
            ret_val = 0;
            break;
        case EM_FX66:
            strcpy(msg, "EM_FX66");
            ret_val = 0;
            break;
        case EM_ST9PLUS:
            strcpy(msg, "EM_ST9PLUS");
            ret_val = 0;
            break;
        case EM_ST7:
            strcpy(msg, "EM_ST7");
            ret_val = 0;
            break;
        case EM_68HC16:
            strcpy(msg, "EM_68HC16");
            ret_val = 0;
            break;
        case EM_68HC11:
            strcpy(msg, "EM_68HC11");
            ret_val = 0;
            break;
        case EM_68HC08:
            strcpy(msg, "EM_68HC08");
            ret_val = 0;
            break;
        case EM_68HC05:
            strcpy(msg, "EM_68HC05");
            ret_val = 0;
            break;
        case EM_SVX:
            strcpy(msg, "EM_SVX");
            ret_val = 0;
            break;
        case EM_ST19:
            strcpy(msg, "EM_ST19");
            ret_val = 0;
            break;
        case EM_VAX:
            strcpy(msg, "EM_VAX");
            ret_val = 0;
            break;
        case EM_CRIS:
            strcpy(msg, "EM_CRIS");
            ret_val = 0;
            break;
        case EM_JAVELIN:
            strcpy(msg, "EM_JAVELIN");
            ret_val = 0;
            break;
        case EM_FIREPATH:
            strcpy(msg, "EM_FIREPATH");
            ret_val = 0;
            break;
        case EM_ZSP:
            strcpy(msg, "EM_ZSP");
            ret_val = 0;
            break;
        case EM_MMIX:
            strcpy(msg, "EM_MMIX");
            ret_val = 0;
            break;
        case EM_HUANY:
            strcpy(msg, "EM_HUANY");
            ret_val = 0;
            break;
        case EM_PRISM:
            strcpy(msg, "EM_PRISM");
            ret_val = 0;
            break;
        case EM_AVR:
            strcpy(msg, "EM_AVR");
            ret_val = 0;
            break;
        case EM_FR30:
            strcpy(msg, "EM_FR30");
            ret_val = 0;
            break;
        case EM_D10V:
            strcpy(msg, "EM_D10V");
            ret_val = 0;
            break;
        case EM_D30V:
            strcpy(msg, "EM_D30V");
            ret_val = 0;
            break;
        case EM_V850:
            strcpy(msg, "EM_V850");
            ret_val = 0;
            break;
        case EM_M32R:
            strcpy(msg, "EM_M32R");
            ret_val = 0;
            break;
        case EM_MN10300:
            strcpy(msg, "EM_MN10300");
            ret_val = 0;
            break;
        case EM_MN10200:
            strcpy(msg, "EM_MN10200");
            ret_val = 0;
            break;
        case EM_PJ:
            strcpy(msg, "EM_PJ");
            ret_val = 0;
            break;
        case EM_OPENRISC:
            strcpy(msg, "EM_OPENRISC");
            ret_val = 0;
            break;
        case EM_ARC_COMPACT:
            strcpy(msg, "EM_ARC_COMPACT");
            ret_val = 0;
            break;
        case EM_XTENSA:
            strcpy(msg, "EM_XTENSA");
            ret_val = 0;
            break;
        case EM_VIDEOCORE:
            strcpy(msg, "EM_VIDEOCORE");
            ret_val = 0;
            break;
        case EM_TMM_GPP:
            strcpy(msg, "EM_TMM_GPP");
            ret_val = 0;
            break;
        case EM_NS32K:
            strcpy(msg, "EM_NS32K");
            ret_val = 0;
            break;
        case EM_TPC:
            strcpy(msg, "EM_TPC");
            ret_val = 0;
            break;
        case EM_SNP1K:
            strcpy(msg, "EM_SNP1K");
            ret_val = 0;
            break;
        case EM_ST200:
            strcpy(msg, "EM_ST200");
            ret_val = 0;
            break;
        case EM_IP2K:
            strcpy(msg, "EM_IP2K");
            ret_val = 0;
            break;
        case EM_MAX:
            strcpy(msg, "EM_MAX");
            ret_val = 0;
            break;
        case EM_CR:
            strcpy(msg, "EM_CR");
            ret_val = 0;
            break;
        case EM_F2MC16:
            strcpy(msg, "EM_F2MC16");
            ret_val = 0;
            break;
        case EM_MSP430:
            strcpy(msg, "EM_MSP430");
            ret_val = 0;
            break;
        case EM_BLACKFIN:
            strcpy(msg, "EM_BLACKFIN");
            ret_val = 0;
            break;
        case EM_SE_C33:
            strcpy(msg, "EM_SE_C33");
            ret_val = 0;
            break;
        case EM_SEP:
            strcpy(msg, "EM_SEP");
            ret_val = 0;
            break;
        case EM_ARCA:
            strcpy(msg, "EM_ARCA");
            ret_val = 0;
            break;
        case EM_UNICORE:
            strcpy(msg, "EM_UNICORE");
            ret_val = 0;
            break;
        case EM_EXCESS:
            strcpy(msg, "EM_EXCESS");
            ret_val = 0;
            break;
        case EM_DXP:
            strcpy(msg, "EM_DXP");
            ret_val = 0;
            break;
        case EM_ALTERA_NIOS2:
            strcpy(msg, "EM_ALTERA_NIOS2");
            ret_val = 0;
            break;
        case EM_CRX:
            strcpy(msg, "EM_CRX");
            ret_val = 0;
            break;
        case EM_XGATE:
            strcpy(msg, "EM_XGATE");
            ret_val = 0;
            break;
        case EM_C166:
            strcpy(msg, "EM_C166");
            ret_val = 0;
            break;
        case EM_M16C:
            strcpy(msg, "EM_M16C");
            ret_val = 0;
            break;
        case EM_DSPIC30F:
            strcpy(msg, "EM_DSPIC30F");
            ret_val = 0;
            break;
        case EM_CE:
            strcpy(msg, "EM_CE");
            ret_val = 0;
            break;
        case EM_M32C:
            strcpy(msg, "EM_M32C");
            ret_val = 0;
            break;
        case EM_TSK3000:
            strcpy(msg, "EM_TSK3000");
            ret_val = 0;
            break;
        case EM_RS08:
            strcpy(msg, "EM_RS08");
            ret_val = 0;
            break;
        case EM_SHARC:
            strcpy(msg, "EM_SHARC");
            ret_val = 0;
            break;
        case EM_ECOG2:
            strcpy(msg, "EM_ECOG2");
            ret_val = 0;
            break;
        case EM_SCORE7:
            strcpy(msg, "EM_SCORE7");
            ret_val = 0;
            break;
        case EM_DSP24:
            strcpy(msg, "EM_DSP24");
            ret_val = 0;
            break;
        case EM_VIDEOCORE3:
            strcpy(msg, "EM_VIDEOCORE3");
            ret_val = 0;
            break;
        case EM_LATTICEMICO32:
            strcpy(msg, "EM_LATTICEMICO32");
            ret_val = 0;
            break;
        case EM_SE_C17:
            strcpy(msg, "EM_SE_C17");
            ret_val = 0;
            break;
        case EM_TI_C6000:
            strcpy(msg, "EM_TI_C6000");
            ret_val = 0;
            break;
        case EM_TI_C2000:
            strcpy(msg, "EM_TI_C2000");
            ret_val = 0;
            break;
        case EM_TI_C5500:
            strcpy(msg, "EM_TI_C5500");
            ret_val = 0;
            break;
        case EM_TI_ARP32:
            strcpy(msg, "EM_TI_ARP32");
            ret_val = 0;
            break;
        case EM_TI_PRU:
            strcpy(msg, "EM_TI_PRU");
            ret_val = 0;
            break;
        case EM_MMDSP_PLUS:
            strcpy(msg, "EM_MMDSP_PLUS");
            ret_val = 0;
            break;
        case EM_CYPRESS_M8C:
            strcpy(msg, "EM_CYPRESS_M8C");
            ret_val = 0;
            break;
        case EM_R32C:
            strcpy(msg, "EM_R32C");
            ret_val = 0;
            break;
        case EM_TRIMEDIA:
            strcpy(msg, "EM_TRIMEDIA");
            ret_val = 0;
            break;
        case EM_QDSP6:
            strcpy(msg, "EM_QDSP6");
            ret_val = 0;
            break;
        case EM_8051:
            strcpy(msg, "EM_8051");
            ret_val = 0;
            break;
        case EM_STXP7X:
            strcpy(msg, "EM_STXP7X");
            ret_val = 0;
            break;
        case EM_NDS32:
            strcpy(msg, "EM_NDS32");
            ret_val = 0;
            break;
        case EM_ECOG1X:
            strcpy(msg, "EM_ECOG1X");
            ret_val = 0;
            break;
        case EM_MAXQ30:
            strcpy(msg, "EM_MAXQ30");
            ret_val = 0;
            break;
        case EM_XIMO16:
            strcpy(msg, "EM_XIMO16");
            ret_val = 0;
            break;
        case EM_MANIK:
            strcpy(msg, "EM_MANIK");
            ret_val = 0;
            break;
        case EM_CRAYNV2:
            strcpy(msg, "EM_CRAYNV2");
            ret_val = 0;
            break;
        case EM_RX:
            strcpy(msg, "EM_RX");
            ret_val = 0;
            break;
        case EM_METAG:
            strcpy(msg, "EM_METAG");
            ret_val = 0;
            break;
        case EM_MCST_ELBRUS:
            strcpy(msg, "EM_MCST_ELBRUS");
            ret_val = 0;
            break;
        case EM_ECOG16:
            strcpy(msg, "EM_ECOG16");
            ret_val = 0;
            break;
        case EM_CR16:
            strcpy(msg, "EM_CR16");
            ret_val = 0;
            break;
        case EM_ETPU:
            strcpy(msg, "EM_ETPU");
            ret_val = 0;
            break;
        case EM_SLE9X:
            strcpy(msg, "EM_SLE9X");
            ret_val = 0;
            break;
        case EM_L10M:
            strcpy(msg, "EM_L10M");
            ret_val = 0;
            break;
        case EM_K10M:
            strcpy(msg, "EM_K10M");
            ret_val = 0;
            break;
        case EM_AARCH64:
            strcpy(msg, "EM_AARCH64");
            ret_val = 0;
            break;
        case EM_AVR32:
            strcpy(msg, "EM_AVR32");
            ret_val = 0;
            break;
        case EM_STM8:
            strcpy(msg, "EM_STM8");
            ret_val = 0;
            break;
        case EM_TILE64:
            strcpy(msg, "EM_TILE64");
            ret_val = 0;
            break;
        case EM_TILEPRO:
            strcpy(msg, "EM_TILEPRO");
            ret_val = 0;
            break;
        case EM_MICROBLAZE:
            strcpy(msg, "EM_MICROBLAZE");
            ret_val = 0;
            break;
        case EM_CUDA:
            strcpy(msg, "EM_CUDA");
            ret_val = 0;
            break;
        case EM_TILEGX:
            strcpy(msg, "EM_TILEGX");
            ret_val = 0;
            break;
        case EM_CLOUDSHIELD:
            strcpy(msg, "EM_CLOUDSHIELD");
            ret_val = 0;
            break;
        case EM_COREA_1ST:
            strcpy(msg, "EM_COREA_1ST");
            ret_val = 0;
            break;
        case EM_COREA_2ND:
            strcpy(msg, "EM_COREA_2ND");
            ret_val = 0;
            break;
        case EM_ARC_COMPACT2:
            strcpy(msg, "EM_ARC_COMPACT2");
            ret_val = 0;
            break;
        case EM_OPEN8:
            strcpy(msg, "EM_OPEN8");
            ret_val = 0;
            break;
        case EM_RL78:
            strcpy(msg, "EM_RL78");
            ret_val = 0;
            break;
        case EM_VIDEOCORE5:
            strcpy(msg, "EM_VIDEOCORE5");
            ret_val = 0;
            break;
        case EM_78KOR:
            strcpy(msg, "EM_78KOR");
            ret_val = 0;
            break;
        case EM_56800EX:
            strcpy(msg, "EM_56800EX");
            ret_val = 0;
            break;
        case EM_BA1:
            strcpy(msg, "EM_BA1");
            ret_val = 0;
            break;
        case EM_BA2:
            strcpy(msg, "EM_BA2");
            ret_val = 0;
            break;
        case EM_XCORE:
            strcpy(msg, "EM_XCORE");
            ret_val = 0;
            break;
        case EM_MCHP_PIC:
            strcpy(msg, "EM_MCHP_PIC");
            ret_val = 0;
            break;
        case EM_INTEL205:
            strcpy(msg, "EM_INTEL205");
            ret_val = 0;
            break;
        case EM_INTEL206:
            strcpy(msg, "EM_INTEL206");
            ret_val = 0;
            break;
        case EM_INTEL207:
            strcpy(msg, "EM_INTEL207");
            ret_val = 0;
            break;
        case EM_INTEL208:
            strcpy(msg, "EM_INTEL208");
            ret_val = 0;
            break;
        case EM_INTEL209:
            strcpy(msg, "EM_INTEL209");
            ret_val = 0;
            break;
        case EM_KM32:
            strcpy(msg, "EM_KM32");
            ret_val = 0;
            break;
        case EM_KMX32:
            strcpy(msg, "EM_KMX32");
            ret_val = 0;
            break;
        case EM_KMX16:
            strcpy(msg, "EM_KMX16");
            ret_val = 0;
            break;
        case EM_KMX8:
            strcpy(msg, "EM_KMX8");
            ret_val = 0;
            break;
        case EM_KVARC:
            strcpy(msg, "EM_KVARC");
            ret_val = 0;
            break;
        case EM_CDP:
            strcpy(msg, "EM_CDP");
            ret_val = 0;
            break;
        case EM_COGE:
            strcpy(msg, "EM_COGE");
            ret_val = 0;
            break;
        case EM_COOL:
            strcpy(msg, "EM_COOL");
            ret_val = 0;
            break;
        case EM_NORC:
            strcpy(msg, "EM_NORC");
            ret_val = 0;
            break;
        case EM_CSR_KALIMBA:
            strcpy(msg, "EM_CSR_KALIMBA");
            ret_val = 0;
            break;
        case EM_Z80:
            strcpy(msg, "EM_Z80");
            ret_val = 0;
            break;
        case EM_VISIUM:
            strcpy(msg, "EM_VISIUM");
            ret_val = 0;
            break;
        case EM_FT32:
            strcpy(msg, "EM_FT32");
            ret_val = 0;
            break;
        case EM_MOXIE:
            strcpy(msg, "EM_MOXIE");
            ret_val = 0;
            break;
        case EM_AMDGPU:
            strcpy(msg, "EM_AMDGPU");
            ret_val = 0;
            break;
        case EM_RISCV:
            strcpy(msg, "EM_RISCV");
            ret_val = 0;
            break;
        case EM_LANAI:
            strcpy(msg, "EM_LANAI");
            ret_val = 0;
            break;
        case EM_CEVA:
            strcpy(msg, "EM_CEVA");
            ret_val = 0;
            break;
        case EM_CEVA_X2:
            strcpy(msg, "EM_CEVA_X2");
            ret_val = 0;
            break;
        case EM_BPF:
            strcpy(msg, "EM_BPF");
            ret_val = 0;
            break;
        case EM_GRAPHCORE_IPU:
            strcpy(msg, "EM_GRAPHCORE_IPU");
            ret_val = 0;
            break;
        case EM_IMG1:
            strcpy(msg, "EM_IMG1");
            ret_val = 0;
            break;
        case EM_NFP:
            strcpy(msg, "EM_NFP");
            ret_val = 0;
            break;
        case EM_VE:
            strcpy(msg, "EM_VE");
            ret_val = 0;
            break;
        case EM_CSKY:
            strcpy(msg, "EM_CSKY");
            ret_val = 0;
            break;
        case EM_ARC_COMPACT3_64:
            strcpy(msg, "EM_ARC_COMPACT3_64");
            ret_val = 0;
            break;
        case EM_MCS6502:
            strcpy(msg, "EM_MCS6502");
            ret_val = 0;
            break;
        case EM_ARC_COMPACT3:
            strcpy(msg, "EM_ARC_COMPACT3");
            ret_val = 0;
            break;
        case EM_KVX:
            strcpy(msg, "EM_KVX");
            ret_val = 0;
            break;
        case EM_65816:
            strcpy(msg, "EM_65816");
            ret_val = 0;
            break;
        case EM_LOONGARCH:
            strcpy(msg, "EM_LOONGARCH");
            ret_val = 0;
            break;
        case EM_KF32:
            strcpy(msg, "EM_KF32");
            ret_val = 0;
            break;
        case EM_U16_U8CORE:
            strcpy(msg, "EM_U16_U8CORE");
            ret_val = 0;
            break;
        case EM_TACHYUM:
            strcpy(msg, "EM_TACHYUM");
            ret_val = 0;
            break;
        case EM_56800EF:
            strcpy(msg, "EM_56800EF");
            ret_val = 0;
            break;
        case EM_SBF:
            strcpy(msg, "EM_SBF");
            ret_val = 0;
            break;
        case EM_AIENGINE:
            strcpy(msg, "EM_AIENGINE");
            ret_val = 0;
            break;
        case EM_SIMA_MLA:
            strcpy(msg, "EM_SIMA_MLA");
            ret_val = 0;
            break;
        case EM_BANG:
            strcpy(msg, "EM_BANG");
            ret_val = 0;
            break;
        case EM_LOONGGPU:
            strcpy(msg, "EM_LOONGGPU");
            ret_val = 0;
            break;
        case EM_SW64:
            strcpy(msg, "EM_SW64");
            ret_val = 0;
            break;
        case EM_AIECTRLCODE:
            strcpy(msg, "EM_AIECTRLCODE");
            ret_val = 0;
            break;
        default:
            strcpy(msg, "UNKNOWN ELFMACHINE");
            ret_val = 0;
            break;
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_p_type(const uint64_t p_type, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    if(p_type >= PT_LOOS && p_type <= PT_HIOS)
    {
        strcpy(msg, "OS specific ELFPTYPE");
        ret_val = 0;
    }
    else if(p_type >= PT_LOPROC && p_type <= PT_HIPROC)
    {
        strcpy(msg, "Processor specific ELFPTYPE");
        ret_val = 0;
    }
    else
    {
        switch(p_type)
        {
            case PT_NULL:
                strcpy(msg, "PT_NULL");
                ret_val = 0;
                break;
            case PT_LOAD:
                strcpy(msg, "PT_LOAD");
                ret_val = 0;
                break;
            case PT_DYNAMIC:
                strcpy(msg, "PT_DYNAMIC");
                ret_val = 0;
                break;
            case PT_INTERP:
                strcpy(msg, "PT_INTERP");
                ret_val = 0;
                break;
            case PT_NOTE:
                strcpy(msg, "PT_NOTE");
                ret_val = 0;
                break;
            case PT_SHLIB:
                strcpy(msg, "PT_SHLIB");
                ret_val = 0;
                break;
            case PT_PHDR:
                strcpy(msg, "PT_PHDR");
                ret_val = 0;
                break;
            case PT_TLS:
                strcpy(msg, "PT_TLS");
                ret_val = 0;
                break;
            default:
                strcpy(msg, "UNKNOWN ELFPTYPE");
                ret_val = 0;
                break;
        }
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int verify_s_type(const uint64_t s_type, char *buf)
{
    char msg[MAX_VALIDATION_MSG];
    int  ret_val;

    if(s_type >= SHT_LOOS && s_type <= SHT_HIOS)
    {
        strcpy(msg, "OS specific ELFSTYPE");
        ret_val = 0;
    }
    else if(s_type >= SHT_LOPROC && s_type <= SHT_HIPROC)
    {
        strcpy(msg, "Processor specific ELFSTYPE");
        ret_val = 0;
    }
    else if(s_type >= SHT_LOUSER && s_type <= SHT_HIUSER)
    {
        strcpy(msg, "Application specific ELFSTYPE");
        ret_val = 0;
    }
    else
    {
        switch(s_type)
        {
            case SHT_NULL:
                strcpy(msg, "SHT_NULL");
                ret_val = 0;
                break;
            case SHT_PROGBITS:
                strcpy(msg, "SHT_PROGBITS");
                ret_val = 0;
                break;
            case SHT_SYMTAB:
                strcpy(msg, "SHT_SYMTAB");
                ret_val = 0;
                break;
            case SHT_STRTAB:
                strcpy(msg, "SHT_STRTAB");
                ret_val = 0;
                break;
            case SHT_RELA:
                strcpy(msg, "SHT_RELA");
                ret_val = 0;
                break;
            case SHT_HASH:
                strcpy(msg, "SHT_HASH");
                ret_val = 0;
                break;
            case SHT_DYNAMIC:
                strcpy(msg, "SHT_DYNAMIC");
                ret_val = 0;
                break;
            case SHT_NOTE:
                strcpy(msg, "SHT_NOTE");
                ret_val = 0;
                break;
            case SHT_NOBITS:
                strcpy(msg, "SHT_NOBITS");
                ret_val = 0;
                break;
            case SHT_REL:
                strcpy(msg, "SHT_REL");
                ret_val = 0;
                break;
            case SHT_SHLIB:
                strcpy(msg, "SHT_SHLIB");
                ret_val = 0;
                break;
            case SHT_DYNSYM:
                strcpy(msg, "SHT_DYNSYM");
                ret_val = 0;
                break;
            case SHT_INIT_ARRAY:
                strcpy(msg, "SHT_INIT_ARRAY");
                ret_val = 0;
                break;
            case SHT_FINI_ARRAY:
                strcpy(msg, "SHT_FINI_ARRAY");
                ret_val = 0;
                break;
            case SHT_PREINIT_ARRAY:
                strcpy(msg, "SHT_PREINIT_ARRAY");
                ret_val = 0;
                break;
            case SHT_GROUP:
                strcpy(msg, "SHT_GROUP");
                ret_val = 0;
                break;
            case SHT_SYMTAB_SHNDX:
                strcpy(msg, "SHT_SYMTAB_SHNDX");
                ret_val = 0;
                break;
            case SHT_RELR:
                strcpy(msg, "SHT_RELR");
                ret_val = 0;
                break;
            default:
                strcpy(msg, "UNKNOWN ELFSTYPE");
                ret_val = 0;
                break;
        }
    }

    if(buf != NULL)
    {
        strcpy(buf, msg);
    }
    return ret_val;
}

int convert_elf32_header_to_generic(elf32_header header32, elf_header *header)
{
    int host_endianess;

    if(verify_data(header32.e_ident.ei_data, NULL) == -1)
    {
        return -1;
    }

    host_endianess = determine_endianness();

    if(host_endianess != (header32.e_ident.ei_data == ELFDATA2MSB) ? 0 : 1)
    {
        byte_swap(&header32.e_type, sizeof(header32.e_type));
        byte_swap(&header32.e_machine, sizeof(header32.e_machine));
        byte_swap(&header32.e_version, sizeof(header32.e_version));
        byte_swap(&header32.e_entry, sizeof(header32.e_entry));
        byte_swap(&header32.e_phoff, sizeof(header32.e_phoff));
        byte_swap(&header32.e_shoff, sizeof(header32.e_shoff));
        byte_swap(&header32.e_flags, sizeof(header32.e_flags));
        byte_swap(&header32.e_ehsize, sizeof(header32.e_ehsize));
        byte_swap(&header32.e_phentsize, sizeof(header32.e_phentsize));
        byte_swap(&header32.e_phnum, sizeof(header32.e_phnum));
        byte_swap(&header32.e_shentsize, sizeof(header32.e_shentsize));
        byte_swap(&header32.e_shnum, sizeof(header32.e_shnum));
        byte_swap(&header32.e_shstrndx, sizeof(header32.e_shstrndx));
    }

    header->e_ident     = header32.e_ident;
    header->e_type      = header32.e_type;
    header->e_machine   = header32.e_machine;
    header->e_version   = header32.e_version;
    header->e_entry     = header32.e_entry;
    header->e_phoff     = header32.e_phoff;
    header->e_shoff     = header32.e_shoff;
    header->e_flags     = header32.e_flags;
    header->e_ehsize    = header32.e_ehsize;
    header->e_phentsize = header32.e_phentsize;
    header->e_phnum     = header32.e_phnum;
    header->e_shentsize = header32.e_shentsize;
    header->e_shnum     = header32.e_shnum;
    header->e_shstrndx  = header32.e_shstrndx;

    return 0;
}

int convert_elf64_header_to_generic(elf64_header header64, elf_header *header)
{
    int host_endianess;

    if(verify_data(header64.e_ident.ei_data, NULL) == -1)
    {
        return -1;
    }

    host_endianess = determine_endianness();

    if(host_endianess != (header64.e_ident.ei_data == ELFDATA2MSB) ? 0 : 1)
    {
        byte_swap(&header64.e_type, sizeof(header64.e_type));
        byte_swap(&header64.e_machine, sizeof(header64.e_machine));
        byte_swap(&header64.e_version, sizeof(header64.e_version));
        byte_swap(&header64.e_entry, sizeof(header64.e_entry));
        byte_swap(&header64.e_phoff, sizeof(header64.e_phoff));
        byte_swap(&header64.e_shoff, sizeof(header64.e_shoff));
        byte_swap(&header64.e_flags, sizeof(header64.e_flags));
        byte_swap(&header64.e_ehsize, sizeof(header64.e_ehsize));
        byte_swap(&header64.e_phentsize, sizeof(header64.e_phentsize));
        byte_swap(&header64.e_phnum, sizeof(header64.e_phnum));
        byte_swap(&header64.e_shentsize, sizeof(header64.e_shentsize));
        byte_swap(&header64.e_shnum, sizeof(header64.e_shnum));
        byte_swap(&header64.e_shstrndx, sizeof(header64.e_shstrndx));
    }

    header->e_ident     = header64.e_ident;
    header->e_type      = header64.e_type;
    header->e_machine   = header64.e_machine;
    header->e_version   = header64.e_version;
    header->e_entry     = header64.e_entry;
    header->e_phoff     = header64.e_phoff;
    header->e_shoff     = header64.e_shoff;
    header->e_flags     = header64.e_flags;
    header->e_ehsize    = header64.e_ehsize;
    header->e_phentsize = header64.e_phentsize;
    header->e_phnum     = header64.e_phnum;
    header->e_shentsize = header64.e_shentsize;
    header->e_shnum     = header64.e_shnum;
    header->e_shstrndx  = header64.e_shstrndx;

    return 0;
}

int correct_elf32_pheader_endianness(uint64_t ei_class, elf32_pheader *headers, uint64_t count)
{
    int host_endianess;

    if(verify_data(ei_class, NULL) == -1)
    {
        return -1;
    }

    host_endianess = determine_endianness();

    if(host_endianess != (ei_class == ELFDATA2MSB) ? 0 : 1)
    {
        for(uint64_t i = 0; i < count; i++)
        {
            byte_swap(&headers[i].p_type, sizeof(headers[i].p_type));
            byte_swap(&headers[i].p_offset, sizeof(headers[i].p_offset));
            byte_swap(&headers[i].p_vaddr, sizeof(headers[i].p_vaddr));
            byte_swap(&headers[i].p_paddr, sizeof(headers[i].p_paddr));
            byte_swap(&headers[i].p_filesz, sizeof(headers[i].p_filesz));
            byte_swap(&headers[i].p_memsz, sizeof(headers[i].p_memsz));
            byte_swap(&headers[i].p_flags, sizeof(headers[i].p_flags));
            byte_swap(&headers[i].p_align, sizeof(headers[i].p_align));
        }
    }

    return 0;
}

int correct_elf64_pheader_endianness(uint64_t ei_class, elf64_pheader *headers, uint64_t count)
{
    int host_endianess;

    if(verify_data(ei_class, NULL) == -1)
    {
        return -1;
    }

    host_endianess = determine_endianness();

    if(host_endianess != (ei_class == ELFDATA2MSB) ? 0 : 1)
    {
        for(uint64_t i = 0; i < count; i++)
        {
            byte_swap(&headers[i].p_type, sizeof(headers[i].p_type));
            byte_swap(&headers[i].p_offset, sizeof(headers[i].p_offset));
            byte_swap(&headers[i].p_vaddr, sizeof(headers[i].p_vaddr));
            byte_swap(&headers[i].p_paddr, sizeof(headers[i].p_paddr));
            byte_swap(&headers[i].p_filesz, sizeof(headers[i].p_filesz));
            byte_swap(&headers[i].p_memsz, sizeof(headers[i].p_memsz));
            byte_swap(&headers[i].p_flags, sizeof(headers[i].p_flags));
            byte_swap(&headers[i].p_align, sizeof(headers[i].p_align));
        }
    }

    return 0;
}

int correct_elf32_sheader_endianness(uint64_t ei_class, elf32_sheader *headers, uint64_t count)
{
    int host_endianess;

    if(verify_data(ei_class, NULL) == -1)
    {
        return -1;
    }

    host_endianess = determine_endianness();

    if(host_endianess != (ei_class == ELFDATA2MSB) ? 0 : 1)
    {
        for(uint64_t i = 0; i < count; i++)
        {
            byte_swap(&headers[i].s_name, sizeof(headers[i].s_name));
            byte_swap(&headers[i].s_type, sizeof(headers[i].s_type));
            byte_swap(&headers[i].s_flags, sizeof(headers[i].s_flags));
            byte_swap(&headers[i].s_addr, sizeof(headers[i].s_addr));
            byte_swap(&headers[i].s_offset, sizeof(headers[i].s_offset));
            byte_swap(&headers[i].s_size, sizeof(headers[i].s_size));
            byte_swap(&headers[i].s_link, sizeof(headers[i].s_link));
            byte_swap(&headers[i].s_info, sizeof(headers[i].s_info));
            byte_swap(&headers[i].s_addralign, sizeof(headers[i].s_addralign));
            byte_swap(&headers[i].s_entsize, sizeof(headers[i].s_entsize));
        }
    }

    return 0;
}

int correct_elf64_sheader_endianness(uint64_t ei_class, elf64_sheader *headers, uint64_t count)
{
    int host_endianess;

    if(verify_data(ei_class, NULL) == -1)
    {
        return -1;
    }

    host_endianess = determine_endianness();

    if(host_endianess != (ei_class == ELFDATA2MSB) ? 0 : 1)
    {
        for(uint64_t i = 0; i < count; i++)
        {
            byte_swap(&headers[i].s_name, sizeof(headers[i].s_name));
            byte_swap(&headers[i].s_type, sizeof(headers[i].s_type));
            byte_swap(&headers[i].s_flags, sizeof(headers[i].s_flags));
            byte_swap(&headers[i].s_addr, sizeof(headers[i].s_addr));
            byte_swap(&headers[i].s_offset, sizeof(headers[i].s_offset));
            byte_swap(&headers[i].s_size, sizeof(headers[i].s_size));
            byte_swap(&headers[i].s_link, sizeof(headers[i].s_link));
            byte_swap(&headers[i].s_info, sizeof(headers[i].s_info));
            byte_swap(&headers[i].s_addralign, sizeof(headers[i].s_addralign));
            byte_swap(&headers[i].s_entsize, sizeof(headers[i].s_entsize));
        }
    }

    return 0;
}
