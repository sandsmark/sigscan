#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <libgen.h>
#include <sys/types.h>
#include <elf.h>

#include <sigscan.h>


//---[ default handler ]---------------------------------------------------------------------------
u32 _def_handler(s8 *data, u32 offset, u32 idx)
{
   //printf("org offset: 0x%08x, magic offset: %d\n", offset, signatures[idx].magic_offset);
   printf("\n\t0x%08x: [type: data, len: %.4d]  %s\n", 
      offset,
      signatures[idx].magic_len, 
      signatures[idx].name); 

   return signatures[idx].magic_len; 
}

//---[ ELF ] --------------------------------------------------------------------------------------
u32 _elf_handler(s8 *data, u32 offset, u32 idx)
{
   Elf32_Ehdr *ehdr = (Elf32_Ehdr *)&data[offset];
   char *class, *bits, *type, *machine;
   int ret;

   ret = 0;
   switch(ehdr->e_ident[EI_CLASS]) {
      case 0: bits = "invalid class"; break;
      case 1: bits = "32-bit"; break;
      case 2: bits = "64-bit"; break;
      default: goto out;
   }

   switch(ehdr->e_ident[EI_DATA]) {
      case 0: class = "Invalid data encoding"; break;
      case 1: class = "LSB"; break;
      case 2: class = "MSB"; break;
      default: goto out;
   }

   switch(ehdr->e_type) {
      case 1: type = "relocatable"; break;
      case 2: type = "executable"; break;
      case 3: type = "shared object"; break;
      case 4: type = "core"; break;
      default: goto out;
   }

   switch(ehdr->e_machine) {
      case 0: machine="No machine"; break;
      case 1: machine="AT&T WE 32100"; break;
      case 2: machine="SPARC"; break;
      case 3: machine="Intel"; break;
      case 4: machine="Motorola 68000"; break;
      case 5: machine="Motorola 88000"; break;
      case 7: machine="Intel 80860"; break;
      case 8: machine="MIPS I"; break;
      case 10:machine="MIPS RS3000 LE"; break;
      case 15:machine="Hewlett-Packard PA-RISC"; break;
      case 17:machine="Fujitsu VPP500"; break;
      case 18:machine="Enhanced instruction set SPARC"; break;
      case 19:machine="Intel 80960"; break;
      case 20:machine="Power PC"; break;
      case 36:machine="NEC V800"; break;
      case 37:machine="Fujitsu FR20"; break;
      case 38:machine="TRW RH-32"; break;
      case 39:machine="Motorola RCE"; break;
      case 40:machine="Advanced RISC Machines ARM"; break;
      case 41:machine="Digital Alpha"; break;
      case 42:machine="Hitachi SH"; break;
      case 43:machine="SPARC Version 9"; break;
      case 44:machine="Siemens Tricore embedded processor"; break;
      case 45:machine="Argonaut RISC Core, Argonaut Technologies Inc."; break;
      case 46:machine="Hitachi H8/300"; break;
      case 47:machine="Hitachi H8/300H"; break;
      case 48:machine="Hitachi H8S"; break;
      case 49:machine="Hitachi H8/500"; break;
      case 50:machine="Intel MercedTM Processor"; break;
      case 51:machine="Stanford MIPS-X"; break;
      case 52:machine="Motorola Coldfire"; break;
      case 53:machine="Motorola M68HC12"; break;
      case 89:machine="Matsushita MN10300"; break;
      //default: goto out;
      default: { 
         printf("machine = %d\n", ehdr->e_machine); machine="unknown";
      }
   }

   printf("\n\t0x%08x: ELF {\n", offset);
   printf("\t   machine: %s\n", machine);
   printf("\t   class:   %s\n", class);
   printf("\t   bits:    %s\n", bits);
   printf("\t   type:    %s\n", type);
   printf("\t}\n");

   //printf("\t0x%08x:  ELF %s %s %s %s\n", offset, class, machine, bits, type);

   ret = signatures[idx].magic_len + sizeof(*ehdr);
out:
   return ret;
}

//---[ ROMFS ]-------------------------------------------------------------------------------------
struct romfs_super_block {
   u32 word0;
   u32 word1;
   u32 size;
   u32 checksum;
   s8 name[0]; /* volume name */
}__attribute__((packed));

u32 _romfs_handler(s8 *data, u32 offset, u32 idx)
{
   struct romfs_super_block *sb = (typeof(sb))&data[offset];
   u32 name_len;
   u32 rc;

   printf("\n\t0x%08x: ROMFS {\n", offset);
   printf("\t   0x%08x: word0:     0x%08x\n", (u32)&sb->word0 - (u32)&sb, sb->word0);
   printf("\t   0x%08x: word1:     0x%08x\n", (u32)&sb->word1 - (u32)&sb, sb->word1);
   printf("\t   0x%08x: size:      0x%08x\n", (u32)&sb->size  - (u32)&sb, sb->size);
   printf("\t   0x%08x: checksum:  0x%08x\n", (u32)&sb->checksum - (u32)&sb, sb->checksum);

   rc = 0;
   for (name_len = 0; sb->name[name_len]; name_len++) 
      if (!isprint(sb->name[name_len]))
         return rc;

   printf("\t   0x%08x: name:      %s\n", (u32)&sb - (u32)sb->name, sb->name);
   printf("\t};\n");

   rc = sizeof(*sb) - signatures[idx].magic_len + name_len;
   return rc;
}
//---[ SQUASH FS ]---------------------------------------------------------------------------------

struct squashfs_super_block {
	u32 s_magic;
	u32 inodes;
	u32 bytes_used_2;
	u32 uid_start_2;
	u32 guid_start_2;
	u32 inode_table_start_2;
	u32 directory_table_start_2;
	u32 s_major:16;
	u32 s_minor:16;
	u32 block_size_1:16;
	u32 block_log:16;
	u32 flags:8;
	u32 no_uids:8;
	u32 no_guids:8;
	u32 mkfs_time /* time of filesystem creation */;
	u64 root_inode;
	u32 block_size;
	u32 fragments;
	u32 fragment_table_start_2;
	s64 bytes_used;
	s64 uid_start;
	s64 guid_start;
	s64 inode_table_start;
	s64 directory_table_start;
	s64 fragment_table_start;
	s64 lookup_table_start;
} __attribute__ ((packed));

u32 _squashfs_handler(s8 *data, u32 offset, u32 idx)
{
   struct squashfs_super_block *sb = (typeof(sb)) &data[offset];

   printf("\n\t0x%08x: SQUASHFS {\n", offset);
   printf("\t   0x%08x: magic:     0x%08x\n", (u32)sb->s_magic - (u32)sb, sb->s_magic);
   printf("\t   0x%08x: inodes:    0x%08x\n", (u32)sb->inodes - (u32)sb, sb->inodes);
   printf("\t   0x%08x: size:      0x%08x\n", (u32)&sb->bytes_used_2 - (u32)&sb, sb->bytes_used_2);
   printf("\t   0x%08x: date:      %s\n", (u32)&sb->mkfs_time - (u32)&sb, ctime((time_t *)&sb->mkfs_time));
   //printf("\t   0x%08x: crc:       0x%08x\n", (u32)&sb->fsid.crc - (u32)&sb, sb->fsid.crc);

   printf("\t};\n");

   return sizeof(*sb) - signatures[idx].magic_len; 
}
//---[ CRAMFS ]------------------------------------------------------------------------------------
struct cramfs_info {
	u32 crc;
	u32 edition;
	u32 blocks;
	u32 files;
}__attribute__((packed));

struct cramfs_super {
	u32 magic;			      /* 0x28cd3d45 - random number */
	u32 size;			      /* length in bytes */
	u32 flags;			      /* feature flags */
	u32 future;			      /* reserved for future use */
	u8 signature[16];		   /* "Compressed ROMFS" */
	struct cramfs_info fsid;/* unique filesystem info */
	u8 name[16];
}__attribute__((packed));

u32 _cramfs_handler(s8 *data, u32 offset, u32 idx)
{
   struct cramfs_super *sb = (typeof(sb)) &data[offset];
   u32 i;
   u32 rc;

   printf("\n\t0x%08x: CRAMFS {\n", offset);
   printf("\t   0x%08x: magic:     0x%08x\n", (u32)sb->magic - (u32)sb, sb->magic);
   printf("\t   0x%08x: size:      0x%08x\n", (u32)&sb->size - (u32)&sb, sb->size);
   printf("\t   0x%08x: crc:       0x%08x\n", (u32)&sb->fsid.crc - (u32)&sb, sb->fsid.crc);

   rc = sizeof(*sb) - signatures[idx].magic_len;
   for (i = 0; sb->name[i]; i++) 
      if (!isprint(sb->name[i]))
         goto out;
   rc += i;
   printf("\t   0x%08x: name:      \"%s\"\n", (u32)&sb->name - (u32)&sb, sb->name);
out:
   printf("\t};\n");

   return sizeof(*sb) - signatures[idx].magic_len; 
}

//---[ ARM exception vector ]----------------------------------------------------------------------
u32 _vector_handler(s8 *data, u32 offset, u32 idx)
{
   printf("\n\t0x%08x: ARM exception vector table {\n", offset);
   printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // reset vector\n", offset);
   printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // undefined instruction vector\n", offset + 0x4);
   printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // software interrupt vector (SWI)\n", offset + 0x8);
   printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // abort prefetch vector\n", offset + 0xc);
   printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // address exception trap\n", offset + 0x10);
   printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // interrupt request vector (IRQ)\n", offset + 0x14);
   printf("\t   0x%08x: 18f09fe5  ldr  pc, [pc, #0x18]; // fast interrupt request vector (FIQ)\n", offset + 0x18);
   printf("\t};\n");

   return signatures[idx].magic_len; 
}

//---[ Mediatek bootloader ]-----------------------------------------------------------------------
typedef struct _BOOTLHeader_ {
   s8   ID1[12];     // BOOTLOADER!\0
   s8   version[4];    
   u32  length;        
   u32  startAddr;    
   u32  checksum;     
   u8   ID2[8];      // NFIINFO\0
   u8   NFIinfo[6];  
   u16  pagesPerBlock;
   u16  totalBlocks;
   u16  blockShift;
   u16  linkAddr[6];
   u16  lastBlock;
} BOOTL_HEADER;

u32 _mtek(s8 *data, u32 offset, u32 idx)
{
   BOOTL_HEADER *bh;

   bh = (BOOTL_HEADER *)data;

   if (strncmp(bh->ID2, "NFIINFO", strlen("NFIINFO")))
      return 0;

   printf("\n\t0x%08x: Mediatek bootloader {\n", offset);
   printf("\t   0x%08x   ID1:          \"%s\"\n", (u32)&bh->ID1 - (u32)&bh, bh->ID1);
   printf("\t   0x%08x   version:      \"%s\"\n", (u32)&bh->version - (u32)&bh, bh->version);
   printf("\t   0x%08x   length:       0x%08x\n", (u32)&bh->length - (u32)&bh, ntohl(bh->length));
   printf("\t   0x%08x   start addr:   0x%08x\n", (u32)&bh->startAddr - (u32)&bh, ntohl(bh->startAddr));
   printf("\t   0x%08x   checksum:     0x%08x\n", (u32)&bh->checksum - (u32)&bh, ntohl(bh->checksum));
   printf("\t   0x%08x   ID2:          \"%s\"\n", (u32)&bh->ID2 - (u32)&bh, bh->ID2);
   printf("\t   0x%08x   NFIinfo:      %02X%02x%02X%02X%02X%02X\n", (u32)&bh->NFIinfo - (u32)&bh,
      bh->NFIinfo[0], bh->NFIinfo[1], bh->NFIinfo[2], bh->NFIinfo[3], bh->NFIinfo[4], bh->NFIinfo[5]);
   printf("\t   0x%08x   pages/block:  %d\n", (u32)&bh->pagesPerBlock - (u32)&bh, bh->pagesPerBlock);
   printf("\t   0x%08x   total blocks: %d\n", (u32)&bh->totalBlocks - (u32)&bh, bh->totalBlocks);
   printf("\t   0x%08x   link address: %02X%02x%02X%02X%02X%02X\n", (u32)&bh->linkAddr - (u32)&bh, 
      bh->linkAddr[0], bh->linkAddr[1], bh->linkAddr[2], bh->linkAddr[3], bh->linkAddr[4], bh->linkAddr[5]); 
   printf("\t   0x%08x   last block:   %d\n\n", (u32)&bh->lastBlock - (u32)&bh, bh->lastBlock);
   printf("\t};\n");

   return sizeof(*bh)-signatures[idx].magic_len;   
}

//---[ ZIP central header ]------------------------------------------------------------------------
typedef struct zip_central {
   u32 signature; //(0x02014b50)
   u16 version;
   u16 version_needed;
   u16 gps_flag;
   u16 compression;
   u16 last_mod;
   u16 last_date;
   u32 crc;
   u32 compr_size;
   u32 uncompr_size;
   u16 name_len;
   u16 extra_len;
   u16 comment_len;
   u16 disk_num;
   u16 attrib;
   u32 external_attrib;
   u32 rel_offset;
   s8 name[0];
} __attribute__((packed)) zip_central_t;

u32 _zip_central_handler(s8 *data, u32 offset, u32 idx)
{
   struct zip_central *zip = (struct zip_central *) &data[offset];
   s8 name[PATH_MAX];
   u32 i;

   // name verification:
   for (i = 0; i < zip->name_len && zip->name[i]; i++) {
      if (!isprint(zip->name[i]))
         break;
      name[i] = zip->name[i];
   } 
   if (i != zip->name_len)
      return 0;
   name[i] = '\0';

   printf("\n\t0x%08x: ZIP central directory header {\n", offset);
   printf("\t   %-13s \"%s\"\n", "name:", name);
   printf("\t   %-14s 0x%08x\n", "crc:", zip->crc);
   printf("\t   %-14s 0x%08x\n", "compr. size:", zip->compr_size);
   printf("\t   %-14s 0x%08x\n", "uncompr. size:", zip->uncompr_size);
   printf("\t}\n");

   return zip->compr_size;
}

//---[ ZIP local header ]--------------------------------------------------------------------------
typedef struct zip_local {
   u32 signature; //(0x04034b50)
   u16 version_needed;
   u16 gps_flag;
   u16 compression;
   u16 last_mod;
   u16 last_date;
   u32 crc;
   u32 compr_size;
   u32 uncompr_size;
   u16 name_len;
   u16 extra_len;
   s8 name[0];
} __attribute__((packed)) zip_local_t;

u32 _zip_local_handler(s8 *data, u32 offset, u32 idx)
{
   struct zip_local *zip = (struct zip_local *) &data[offset];
   s8 name[PATH_MAX];
   u32 i;

   // name verification:
   for (i = 0; i < zip->name_len && zip->name[i]; i++) {
      if (!isprint(zip->name[i]))
         break;
      name[i] = zip->name[i];
   } 
   if (i != zip->name_len)
      return 0;
   name[i] = '\0';

   printf("\n\t0x%08x: ZIP local file header {\n", offset);
   printf("\t   %-14s \"%s\"\n", "name:", name);
   printf("\t   %-14s 0x%08x\n", "crc:", zip->crc);
   printf("\t   %-14s 0x%08x\n", "compr. size:", zip->compr_size);
   printf("\t   %-14s 0x%08x\n", "uncompr. size:", zip->uncompr_size);
   printf("\t}\n");

   return zip->compr_size;
}

//---[ GZIP ]--------------------------------------------------------------------------------------
#define GZIP_FTEXT      0x01
#define GZIP_FHCRC      0x02
#define GZIP_FEXTRA     0x04
#define GZIP_FNAME      0x08
#define GZIP_FCOMMENT   0x10
#define GZIP_FRESERVED1 0x20
#define GZIP_FRESERVED2 0x40
#define GZIP_FRESERVED3 0x80

typedef struct gzip {
   u8  id1; // 0x1f
   u8  id2; // 0x8b
   u8  cm;  // 0x08
   u8  flg;
   u32 time;
   u8  eflags;
   u8  ostype;
   s8  name[0];
} __attribute__((__packed__)) gzip_t;

u32 _gzip_handler(s8 *data, u32 offset, u32 idx)
{
   struct gzip *gz = (struct gzip *) &data[offset];
   s8 timebuf[26];
   u32 name_len;
   u32 rc;

   rc = 0;
   // name validity check:
   name_len = 0;
   if (gz->flg & GZIP_FNAME) {
      for (name_len = 0; gz->name[name_len]; name_len++) {
         if (!isprint(gz->name[name_len])) 
            return rc;
      }
   } 

   printf("\n\t0x%08x GZIP compressed data {\n", offset);
   if (name_len)
      printf("\t   %-10s \"%s\"\n", "name:", gz->name);

   // compression method:
   printf("\t   %-10s ", "method:");
   switch(gz->cm) {
      case 8: printf("deflate\n", gz->cm); break;
      default: printf("%d\n", gz->cm);
   }

   printf("\t   %-10s ", "type:");
   if (gz->flg & GZIP_FTEXT)
      printf("ASCII\n");
   else
      printf("binary\n");

   printf("\t   %-10s ", "OS type:");
   switch(gz->ostype) {
      case 0: printf("FAT based\n"); break;
      case 1: printf("Amiga\n"); break;
      case 2: printf("VMS\n"); break;
      case 3: printf("Unix\n"); break;
      case 4: printf("VM/CMS\n"); break;
      case 5: printf("Atari TOS\n"); break;
      case 6: printf("HPFS based\n"); break;
      case 7: printf("Macintosh\n"); break;
      case 8: printf("Z-System\n"); break;
      case 9: printf("CP/M\n"); break;
      case 10:printf("TOPS-20\n"); break;
      case 11:printf("NTFS based\n"); break;
      case 12:printf("QDOS\n"); break;
      case 13:printf("Acorn RISCOS\n"); break;
      default: printf("[unknown: %d]\n", gz->ostype);
   }

   ctime_r((time_t *)&gz->time, timebuf);
   timebuf[strlen(timebuf)-1] = '\0';
   printf("\t   %-10s %s\n", "date:", timebuf);
   printf("\t}\n");

   rc = sizeof(*gz) - signatures[idx].magic_len; 

   return rc;
}

