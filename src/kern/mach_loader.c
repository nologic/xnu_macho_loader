

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/fcntl.h>
#include <sys/imgact.h>

#include <mach/mach_types.h>
#include <mach/vm_map.h>	/* vm_allocate() */
#include <mach/vm_param.h>
#include <mach/mach_vm.h>	/* mach_vm_allocate() */
#include <mach/vm_statistics.h>
#include <mach/task.h>
#include <mach/thread_act.h>

#include <machine/vmparam.h>

#include <kern/kern_types.h>
#include <kern/mach_loader.h>
#include <kern/mach_fat.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <vm/vm_kern.h>
#include <IOKit/IOReturn.h>	/* for kIOReturnNotPrivileged */

/*
 * XXX vm/pmap.h should not treat these prototypes as MACH_KERNEL_PRIVATE
 * when KERNEL is defined.
 */

char* load_to_string(int load) {
    switch (load) {
        case LOAD_SUCCESS: return("LOAD_SUCCESS");
        case LOAD_BADARCH: return("LOAD_BADARCH");
        case LOAD_BADMACHO: return("LOAD_BADMACHO");
        case LOAD_SHLIB: return("LOAD_SHLIB");
        case LOAD_FAILURE: return("LOAD_FAILURE");
        case LOAD_NOSPACE: return("LOAD_NOSPACE");
        case LOAD_PROTECT: return("LOAD_PROTECT");
        case LOAD_RESOURCE: return("LOAD_RESOURCE");
        case LOAD_ENOENT: return("LOAD_ENOENT");
        case LOAD_IOERROR: return("LOAD_IOERROR");
        case LOAD_DECRYPTFAIL: return("LOAD_DECRYPTFAIL");
        default:
            return ("LOAD_WTF?!");
    }
}

char* command_to_string(int cmd) {
    switch(cmd) {
        case LC_SEGMENT: return "LC_SEGMENT";
        case LC_SYMTAB: return("LC_SYMTAB"); break;
        case LC_SYMSEG: return("LC_SYMSEG"); break;
        case LC_THREAD: return("LC_THREAD"); break;
        case LC_UNIXTHREAD: return "LC_UNIXTHREAD";
        case LC_LOADFVMLIB: return("LC_LOADFVMLIB"); break;
        case LC_IDFVMLIB: return("LC_IDFVMLIB"); break;
        case LC_IDENT: return("LC_IDENT"); break;
        case LC_FVMFILE: return("LC_FVMFILE"); break;
        case LC_PREPAGE: return("LC_PREPAGE"); break;
        case LC_DYSYMTAB: return("LC_DYSYMTAB"); break;
        case LC_LOAD_DYLIB: return("LC_LOAD_DYLIB"); break;
        case LC_ID_DYLIB: return("LC_ID_DYLIB"); break;
        case LC_LOAD_DYLINKER: return("LC_LOAD_DYLINKER"); break;
        case LC_ID_DYLINKER: return("LC_ID_DYLINKER"); break;
        case LC_PREBOUND_DYLIB: return("LC_PREBOUND_DYLIB"); break;
        case LC_ROUTINES: return("LC_ROUTINES"); break;
        case LC_SUB_FRAMEWORK: return("LC_SUB_FRAMEWORK"); break;
        case LC_SUB_UMBRELLA: return("LC_SUB_UMBRELLA"); break;
        case LC_SUB_CLIENT: return("LC_SUB_CLIENT"); break;
        case LC_SUB_LIBRARY: return("LC_SUB_LIBRARY"); break;
        case LC_TWOLEVEL_HINTS: return("LC_TWOLEVEL_HINTS"); break;
        case LC_PREBIND_CKSUM: return("LC_PREBIND_CKSUM"); break;
            
        default:
            return("Unknown cmd");
            break;
    }
}

#define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24) )

void hexdump(void *tmp, unsigned int size, unsigned long base)
{
    int i;
    
    unsigned char *data = (unsigned char *)tmp;
    
    while (size > 16) {
        for (i=0; i<16; i++) printf("%02x ", data[i]);
        for (i=0; i<16; i++) {
            unsigned char c = data[i];
            if (c < 32 || c > 127) c = '.';
            printf("%c", c);
        }
        printf("\n");
        size -= 16;
        data += 16;
        base += 16;
    }
    for (i=0; i<size; i++) printf("%02x ", data[i]);
    for (i=size; i<16; i++) printf("   ");
    for (i=0; i<size; i++) {
        unsigned char c = data[i];
        if (c < 32 || c > 127) c = '.';
        printf("%c", c);
    }
    printf("\n");
}


/* XXX should have prototypes in a shared header file */
extern int	get_map_nentries(vm_map_t);

extern kern_return_t	memory_object_signed(memory_object_control_t control,
					     boolean_t is_signed);

/* An empty load_result_t */
static load_result_t load_result_null = {
	.mach_header = MACH_VM_MIN_ADDRESS,
	.entry_point = MACH_VM_MIN_ADDRESS,
	.user_stack = MACH_VM_MIN_ADDRESS,
	.user_stack_size = 0,
	.all_image_info_addr = MACH_VM_MIN_ADDRESS,
	.all_image_info_size = 0,
	.thread_count = 0,
	.unixproc = 0,
	.dynlinker = 0,
	.needs_dynlinker = 0,
	.prog_allocated_stack = 0,
	.prog_stack_size = 0,
	.validentry = 0,
	.csflags = 0,
	.uuid = { 0 },
	.min_vm_addr = MACH_VM_MAX_ADDRESS,
	.max_vm_addr = MACH_VM_MIN_ADDRESS
};

/*
 * Prototypes of static functions.
 */
static load_return_t
parse_machfile(
	uint8_t		*vp,
	struct mach_header	*header,
	off_t			file_offset,
	off_t			macho_size,
	int			depth,
	int64_t			slide,
	int64_t			dyld_slide,	
	load_result_t		*result
);

static load_return_t
load_segment(
	struct load_command		*lcp,
	uint32_t			filetype,
	void				*control,
	off_t				pager_offset,
	off_t				macho_size,
	uint8_t			*vp,
	int64_t				slide,
	load_result_t			*result
);

static load_return_t
load_uuid(
	struct uuid_command		*uulp,
	char				*command_end,
	load_result_t			*result
);

static load_return_t
load_code_signature(
	struct linkedit_data_command	*lcp,
	uint8_t			*vp,
	off_t				macho_offset,
	off_t				macho_size,
	cpu_type_t			cputype,
	load_result_t			*result);
	
#if CONFIG_CODE_DECRYPTION
static load_return_t
set_code_unprotect(
	struct encryption_info_command	*lcp,
	caddr_t				addr,
	vm_map_t			map,
	int64_t				slide,
	uint8_t		*vp,
	cpu_type_t			cputype,
	cpu_subtype_t		cpusubtype);
#endif

static
load_return_t
load_main(
	struct entry_point_command	*epc,
	load_result_t		*result
);

static load_return_t
load_unixthread(
	struct thread_command	*tcp,
	load_result_t			*result
);

static load_return_t
load_threadstate(
	thread_t		thread,
	uint32_t	*ts,
	uint32_t	total_size
);

static load_return_t
load_threadstack(
	thread_t		thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*user_stack,
	int				*customstack
);

static load_return_t
load_threadentry(
	thread_t		thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*entry_point
);

static load_return_t
load_dylinker(
	struct dylinker_command	*lcp,
	integer_t		archbits,
	int						depth,
	int64_t			slide,
	load_result_t			*result
);

struct macho_data;

static load_return_t
get_macho_vnode(
	char				*path,
	integer_t		archbits,
	struct mach_header	*mach_header,
	off_t			*file_offset,
	off_t			*macho_size,
	struct macho_data	*macho_data,
	uint8_t		**vpp
);

static inline void
widen_segment_command(const struct segment_command *scp32,
    struct segment_command_64 *scp)
{
	scp->cmd = scp32->cmd;
	scp->cmdsize = scp32->cmdsize;
	bcopy(scp32->segname, scp->segname, sizeof(scp->segname));
	scp->vmaddr = scp32->vmaddr;
	scp->vmsize = scp32->vmsize;
	scp->fileoff = scp32->fileoff;
	scp->filesize = scp32->filesize;
	scp->maxprot = scp32->maxprot;
	scp->initprot = scp32->initprot;
	scp->nsects = scp32->nsects;
	scp->flags = scp32->flags;
}

static void
note_all_image_info_section(const struct segment_command_64 *scp,
    boolean_t is64, size_t section_size, const void *sections,
    int64_t slide, load_result_t *result)
{
	const union {
		struct section s32;
		struct section_64 s64;
	} *sectionp;
	unsigned int i;

	if (strncmp(scp->segname, "__DATA", sizeof(scp->segname)) != 0)
		return;
	for (i = 0; i < scp->nsects; ++i) {
		sectionp = (const void *)
		    ((const char *)sections + section_size * i);
		if (0 == strncmp(sectionp->s64.sectname, "__all_image_info",
		    sizeof(sectionp->s64.sectname))) {
			result->all_image_info_addr =
			    is64 ? sectionp->s64.addr : sectionp->s32.addr;
			result->all_image_info_addr += slide;
			result->all_image_info_size =
			    is64 ? sectionp->s64.size : sectionp->s32.size;
			return;
		}
	}
}

load_return_t
load_machfile(
	struct image_params	*imgp,
	struct mach_header	*header,
	load_result_t		*result
)
{
	// vnode
	uint8_t		*vp = imgp->ip_vp;
	off_t			file_offset = imgp->ip_arch_offset;
	off_t			macho_size = imgp->ip_arch_size;
	off_t			file_size = imgp->ip_vp_size;
    
	load_result_t		myresult;
	load_return_t		lret;

    mach_vm_offset_t	aslr_offset = 0;
	mach_vm_offset_t	dyld_aslr_offset = 0;

	if (macho_size > file_size) {
		return(LOAD_BADMACHO);
	}
	
	if (!result)
		result = &myresult;

	*result = load_result_null;

	lret = parse_machfile(vp, header, file_offset, macho_size,
	                      0, (int64_t)aslr_offset, (int64_t)dyld_aslr_offset, result);
    
    printf("load_machfile: %s\n", load_to_string(lret));

	if (lret != LOAD_SUCCESS) {
		return(lret);
	}
    
	return(LOAD_SUCCESS);
}

/*
 * The file size of a mach-o file is limited to 32 bits; this is because
 * this is the limit on the kalloc() of enough bytes for a mach_header and
 * the contents of its sizeofcmds, which is currently constrained to 32
 * bits in the file format itself.  We read into the kernel buffer the
 * commands section, and then parse it in order to parse the mach-o file
 * format load_command segment(s).  We are only interested in a subset of
 * the total set of possible commands. If "map"==VM_MAP_NULL or
 * "thread"==THREAD_NULL, do not make permament VM modifications,
 * just preflight the parse.
 */
static
load_return_t
parse_machfile(
	uint8_t 		*vp,       
	struct mach_header	*header,
	off_t			file_offset,
	off_t			macho_size,
	int			depth,
	int64_t			aslr_offset,
	int64_t			dyld_aslr_offset,
	load_result_t		*result
)
{
	uint32_t		ncmds;
	struct load_command	*lcp;
	struct dylinker_command	*dlp = 0;
	integer_t		dlarchbits = 0;
	void *			control;
	load_return_t		ret = LOAD_SUCCESS;
	caddr_t			addr;
	vm_size_t		size,kl_size;
	size_t			offset;
	size_t			oldoffset;	/* for overflow check */
	int			pass;
	size_t			mach_header_sz = sizeof(struct mach_header);
	boolean_t		abi64;
	boolean_t		got_code_signatures = FALSE;
	int64_t			slide = 0;

	if (header->magic == MH_MAGIC_64 ||
	    header->magic == MH_CIGAM_64) {
	    	mach_header_sz = sizeof(struct mach_header_64);
	}

	/*
	 *	Break infinite recursion
	 */
	if (depth > 6) {
        printf("parse_machfile 1: %s\n", load_to_string(LOAD_FAILURE));
		return(LOAD_FAILURE);
	}

	depth++;

	/*
	 *	Check to see if right machine type.
	 */
    // this should be implemented by qemu somehow.
	/*if (((cpu_type_t)(header->cputype & ~CPU_ARCH_MASK) != (cpu_type() & ~CPU_ARCH_MASK)) ||
	    !grade_binary(header->cputype, 
	    	header->cpusubtype & ~CPU_SUBTYPE_MASK))
		return(LOAD_BADARCH);*/
		
	abi64 = ((header->cputype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64);
    
	switch (header->filetype) {
	
	case MH_OBJECT:
	case MH_EXECUTE:
	case MH_PRELOAD:
		if (depth != 1) {
            printf("parse_machfile 2: %s\n", load_to_string(LOAD_FAILURE));
			return (LOAD_FAILURE);
		}
		break;
		
	case MH_FVMLIB:
	case MH_DYLIB:
		if (depth == 1) {
            printf("parse_machfile 2: %s\n", load_to_string(LOAD_FAILURE));
			return (LOAD_FAILURE);
		}
		break;

	case MH_DYLINKER:
		if (depth != 2) {
            printf("parse_machfile 3: %s\n", load_to_string(LOAD_FAILURE));
			return (LOAD_FAILURE);
		}
		break;
		
	default:
        printf("parse_machfile 4: %s, header->filetype = %d\n", load_to_string(LOAD_FAILURE), header->filetype);
		return (LOAD_FAILURE);
	}

	/*
	 *	Map portion that must be accessible directly into
	 *	kernel's map.
	 */
    if ((off_t)(mach_header_sz + header->sizeofcmds) > macho_size) {
        printf("parse_machfile 5: %s header->sizeofcmds: %d macho_size %d\n", load_to_string(LOAD_BADMACHO), header->sizeofcmds, macho_size);
		return(LOAD_BADMACHO);
    }

	/*
	 *	Round size of Mach-O commands up to page boundry.
	 */
	size = round_page(mach_header_sz + header->sizeofcmds);
    if (size <= 0) {
        printf("parse_machfile 6: %s\n", load_to_string(LOAD_BADMACHO));
		return(LOAD_BADMACHO);
    }

	/*
	 * Map the load commands into kernel memory.
	 */
	addr = 0;
	kl_size = size;
	addr = (caddr_t)(vp);
    if (addr == NULL) {
        printf("parse_machfile 7: %s\n", load_to_string(LOAD_NOSPACE));
		return(LOAD_NOSPACE);
    }

	/*
	 *	For PIE and dyld, slide everything by the ASLR offset.
	 */
	if ((header->flags & MH_PIE) || (header->filetype == MH_DYLINKER)) {
		slide = aslr_offset;
	}

	 /*
	 *  Scan through the commands, processing each one as necessary.
	 *  We parse in three passes through the headers:
	 *  1: thread state, uuid, code signature
	 *  2: segments
	 *  3: dyld, encryption, check entry point
	 */
	
	for (pass = 1; pass <= 3; pass++) {

		/*
		 * Check that the entry point is contained in an executable segments
		 */ 
		if ((pass == 3) && (result->validentry == 0)) {
			ret = LOAD_FAILURE;
			break;
		}

		/*
		 * Loop through each of the load_commands indicated by the
		 * Mach-O header; if an absurd value is provided, we just
		 * run off the end of the reserved section by incrementing
		 * the offset too far, so we are implicitly fail-safe.
		 */
		offset = mach_header_sz;
		ncmds = header->ncmds;

		while (ncmds--) {
			/*
			 *	Get a pointer to the command.
			 */
			lcp = (struct load_command *)(addr + offset);
			oldoffset = offset;
			offset += lcp->cmdsize;

			/*
			 * Perform prevalidation of the struct load_command
			 * before we attempt to use its contents.  Invalid
			 * values are ones which result in an overflow, or
			 * which can not possibly be valid commands, or which
			 * straddle or exist past the reserved section at the
			 * start of the image.
			 */
			if (oldoffset > offset ||
			    lcp->cmdsize < sizeof(struct load_command) ||
			    offset > header->sizeofcmds + mach_header_sz) {
				ret = LOAD_BADMACHO;
				break;
			}

			/*
			 * Act on struct load_command's for which kernel
			 * intervention is required.
			 */
            printf("Command: %s\n", command_to_string(lcp->cmd));
			switch(lcp->cmd) {
			case LC_SEGMENT:
				if (pass != 2)
					break;

				if (abi64) {
					/*
					 * Having an LC_SEGMENT command for the
					 * wrong ABI is invalid <rdar://problem/11021230>
					 */
					ret = LOAD_BADMACHO;
					break;
				}

				ret = load_segment(lcp,
				                   header->filetype,
				                   control,
				                   file_offset,
				                   macho_size,
				                   vp,
				                   slide,
				                   result);
				break;
			case LC_SEGMENT_64:
				if (pass != 2)
					break;

				if (!abi64) {
					/*
					 * Having an LC_SEGMENT_64 command for the
					 * wrong ABI is invalid <rdar://problem/11021230>
					 */
					ret = LOAD_BADMACHO;
					break;
				}

				ret = load_segment(lcp,
				                   header->filetype,
				                   control,
				                   file_offset,
				                   macho_size,
				                   vp,
				                   slide,
				                   result);
				break;
			case LC_UNIXTHREAD:
				if (pass != 1)
					break;
				ret = load_unixthread(
						 (struct thread_command *) lcp,
						 result);
				break;
			case LC_MAIN:
				if (pass != 1)
					break;
				if (depth != 1)
					break;
				ret = load_main(
						 (struct entry_point_command *) lcp,
						 result);
				break;
			case LC_LOAD_DYLINKER:
				if (pass != 3)
					break;
				if ((depth == 1) && (dlp == 0)) {
					dlp = (struct dylinker_command *)lcp;
					dlarchbits = (header->cputype & CPU_ARCH_MASK);
				} else {
					ret = LOAD_FAILURE;
				}
				break;
			case LC_UUID:
				if (pass == 1 && depth == 1) {
					ret = load_uuid((struct uuid_command *) lcp,
							(char *)addr + mach_header_sz + header->sizeofcmds,
							result);
				}
				break;
			case LC_CODE_SIGNATURE:
				/* CODE SIGNING */
				if (pass != 1)
					break;
				/* pager -> uip ->
				   load signatures & store in uip
				   set VM object "signed_pages"
				*/
				/*ret = load_code_signature(
					(struct linkedit_data_command *) lcp,
					vp,
					file_offset,
					macho_size,
					header->cputype,
					result);*/
				if (ret != LOAD_SUCCESS) {
					printf("proc: load code signature error %d ", ret);
					ret = LOAD_SUCCESS; /* ignore error */
				} else {
					got_code_signatures = TRUE;
				}
				break;
#if CONFIG_CODE_DECRYPTION
			case LC_ENCRYPTION_INFO:
			case LC_ENCRYPTION_INFO_64:
				if (pass != 3)
					break;
				ret = set_code_unprotect(
					(struct encryption_info_command *) lcp,
					addr, map, slide, vp,
					header->cputype, header->cpusubtype);
				if (ret != LOAD_SUCCESS) {
					printf("proc %d: set_code_unprotect() error %d "
					       "for file \"%s\"\n",
					       p->p_pid, ret, vp->v_name);
					/* 
					 * Don't let the app run if it's 
					 * encrypted but we failed to set up the
					 * decrypter. If the keys are missing it will
					 * return LOAD_DECRYPTFAIL.
					 */
					 if (ret == LOAD_DECRYPTFAIL) {
						/* failed to load due to missing FP keys */
						proc_lock(p);
						p->p_lflag |= P_LTERM_DECRYPTFAIL;
						proc_unlock(p);
					}
					 psignal(p, SIGKILL);
				}
				break;
#endif
			default:
				/* Other commands are ignored by the kernel */
				ret = LOAD_SUCCESS;
				break;
			}
            
            printf("parse_machfile 9: ret %s\n", load_to_string(ret));

			if (ret != LOAD_SUCCESS)
				break;
		}
        
		if (ret != LOAD_SUCCESS)
			break;
	}

    if (ret == LOAD_SUCCESS) {
	    if (! got_code_signatures) {
		    //struct cs_blob *blob;
		    /* no embedded signatures: look for detached ones */
		    //blob = ubc_cs_blob_get(vp, -1, file_offset);
		    //if (blob != NULL) {
			//unsigned int cs_flag_data = blob->csb_flags;
			//if(0 != ubc_cs_generation_check(vp)) {
			//	if (0 != ubc_cs_blob_revalidate(vp, blob)) {
			//		/* clear out the flag data if revalidation fails */
			//		cs_flag_data = 0;
			//		result->csflags &= ~CS_VALID;
			//	}
			//}
			/* get flags to be applied to the process */
			//result->csflags |= cs_flag_data;
		    //}
	    }

		/* Make sure if we need dyld, we got it */
		if (result->needs_dynlinker && !dlp) {
			ret = LOAD_FAILURE;
		}

	    if ((ret == LOAD_SUCCESS) && (dlp != 0)) {
			/*
		 	* load the dylinker, and slide it by the independent DYLD ASLR
		 	* offset regardless of the PIE-ness of the main binary.
		 	*/
			ret = load_dylinker(dlp, dlarchbits, depth, dyld_aslr_offset, result);
		}

	    if((ret == LOAD_SUCCESS) && (depth == 1)) {
			if (result->thread_count == 0) {
				ret = LOAD_FAILURE;
			}
	    }
    }
    
    printf("parse_machfile 8: %s\n", load_to_string(ret));

	return(ret);
}

#if CONFIG_CODE_DECRYPTION

#define	APPLE_UNPROTECTED_HEADER_SIZE	(3 * PAGE_SIZE_64)

static load_return_t
unprotect_dsmos_segment(
	uint64_t	file_off,
	uint64_t	file_size,
	uint8_t	*vp,
	off_t		macho_offset,
	vm_map_t	map,
	vm_map_offset_t	map_addr,
	vm_map_size_t	map_size)
{
	kern_return_t	kr;

	/*
	 * The first APPLE_UNPROTECTED_HEADER_SIZE bytes (from offset 0 of
	 * this part of a Universal binary) are not protected...
	 * The rest needs to be "transformed".
	 */
	if (file_off <= APPLE_UNPROTECTED_HEADER_SIZE &&
	    file_off + file_size <= APPLE_UNPROTECTED_HEADER_SIZE) {
		/* it's all unprotected, nothing to do... */
		kr = KERN_SUCCESS;
	} else {
		if (file_off <= APPLE_UNPROTECTED_HEADER_SIZE) {
			/*
			 * We start mapping in the unprotected area.
			 * Skip the unprotected part...
			 */
			vm_map_offset_t	delta;

			delta = APPLE_UNPROTECTED_HEADER_SIZE;
			delta -= file_off;
			map_addr += delta;
			map_size -= delta;
		}
		/* ... transform the rest of the mapping. */
		struct pager_crypt_info crypt_info;
		crypt_info.page_decrypt = dsmos_page_transform;
		crypt_info.crypt_ops = NULL;
		crypt_info.crypt_end = NULL;
#pragma unused(vp, macho_offset)
		crypt_info.crypt_ops = (void *)0x2e69cf40;
		kr = vm_map_apple_protected(map,
					    map_addr,
					    map_addr + map_size,
					    &crypt_info);
	}

	if (kr != KERN_SUCCESS) {
		return LOAD_FAILURE;
	}
	return LOAD_SUCCESS;
}
#else	/* CONFIG_CODE_DECRYPTION */
/*static load_return_t
unprotect_dsmos_segment(
	__unused	uint64_t	file_off,
	__unused	uint64_t	file_size,
	__unused	uint8_t	*vp,
	__unused	off_t		macho_offset,
	__unused	vm_map_offset_t	map_addr,
	__unused	vm_map_size_t	map_size)
{
	return LOAD_SUCCESS;
}*/
#endif	/* CONFIG_CODE_DECRYPTION */

static
load_return_t
load_segment(
	struct load_command		*lcp,
	uint32_t			filetype,
	void *				control,
	off_t				pager_offset,
	off_t				macho_size,
	uint8_t			*vp,
	int64_t				slide,
	load_result_t		*result
)
{
	struct segment_command_64 segment_command, *scp;
	kern_return_t		ret;
	vm_map_offset_t		map_addr, map_offset;
	vm_map_size_t		map_size, seg_size, delta_size;
	vm_prot_t 		initprot;
	vm_prot_t		maxprot;
	size_t			segment_command_size, total_section_size,
				single_section_size;
	
	if (LC_SEGMENT_64 == lcp->cmd) {
		segment_command_size = sizeof(struct segment_command_64);
		single_section_size  = sizeof(struct section_64);
	} else {
		segment_command_size = sizeof(struct segment_command);
		single_section_size  = sizeof(struct section);
	}
    if (lcp->cmdsize < segment_command_size) {
        printf("load_segment 1: %s\n", load_to_string(LOAD_BADMACHO));
        
		return (LOAD_BADMACHO);
    }
    
	total_section_size = lcp->cmdsize - segment_command_size;

	if (LC_SEGMENT_64 == lcp->cmd)
		scp = (struct segment_command_64 *)lcp;
	else {
		scp = &segment_command;
		widen_segment_command((struct segment_command *)lcp, scp);
	}

	/*
	 * Make sure what we get from the file is really ours (as specified
	 * by macho_size).
	 */
	if (scp->fileoff + scp->filesize < scp->fileoff ||
        scp->fileoff + scp->filesize > (uint64_t)macho_size) {
        printf("load_segment 2: %s\n", load_to_string(LOAD_BADMACHO));
		return (LOAD_BADMACHO);
    }
	/*
	 * Ensure that the number of sections specified would fit
	 * within the load command size.
	 */
    if (total_section_size / single_section_size < scp->nsects) {
        printf("load_segment 3: %s\n", load_to_string(LOAD_BADMACHO));
		return (LOAD_BADMACHO);
    }

	/*
	 *	Round sizes to page size.
	 */
	seg_size = scp->vmsize;
	map_size = scp->filesize;
	map_addr = scp->vmaddr; /* JVXXX note that in XNU TOT this is round instead of trunc for 64 bits */

    if (seg_size == 0) {
        printf("load_segment 4: KERN_SUCCESS\n");
		return (KERN_SUCCESS);
    }
    
	if (map_addr == 0 &&
	    map_size == 0 &&
	    seg_size != 0 &&
	    (scp->initprot & VM_PROT_ALL) == VM_PROT_NONE &&
	    (scp->maxprot & VM_PROT_ALL) == VM_PROT_NONE) {
		/*
		 * For PIE, extend page zero rather than moving it.  Extending
		 * page zero keeps early allocations from falling predictably
		 * between the end of page zero and the beginning of the first
		 * slid segment.
		 */
		seg_size += slide;
		slide = 0;

		/*
		 * This is a "page zero" segment:  it starts at address 0,
		 * is not mapped from the binary file and is not accessible.
		 * User-space should never be able to access that memory, so
		 * make it completely off limits by raising the VM map's
		 * minimum offset.
		 */
		return (LOAD_SUCCESS);
	}

	/* If a non-zero slide was specified by the caller, apply now */
	map_addr += slide;

	if (map_addr < result->min_vm_addr)
		result->min_vm_addr = map_addr;
	if (map_addr+seg_size > result->max_vm_addr)
		result->max_vm_addr = map_addr+seg_size;

	map_offset = pager_offset + scp->fileoff;	/* limited to 32 bits */

	if (map_size > 0) {
		initprot = (scp->initprot) & VM_PROT_ALL;
		maxprot = (scp->maxprot) & VM_PROT_ALL;
        
        map_addr = (vm_map_offset_t)mmap((void*)map_addr, map_size, initprot, MAP_PRIVATE | MAP_ANON, 0, 0);
        
        printf("load_segment 5: loaded %p size %d\n", (void*)map_addr, map_size);
		if ((void*)map_addr == MAP_FAILED) {
			return (LOAD_NOSPACE);
		}
	
		/*
		 *	If the file didn't end on a page boundary,
		 *	we need to zero the leftover.
		 */
		delta_size = map_size - scp->filesize;
	}


	if ( (scp->fileoff == 0) && (scp->filesize != 0) )
		result->mach_header = map_addr;


	ret = LOAD_SUCCESS;
    
    if (LOAD_SUCCESS == ret && filetype == MH_DYLINKER && result->all_image_info_addr == MACH_VM_MIN_ADDRESS) {
		note_all_image_info_section(scp,
		    LC_SEGMENT_64 == lcp->cmd, single_section_size,
		    (const char *)lcp + segment_command_size, slide, result);
    }

    printf("load_segment 6: (%p >= %p) && (%p < (%p))\n", result->entry_point, (void*)map_addr, result->entry_point, (void*)(map_addr + map_size));
    
    // QEMU: will need to figure out the entry point somehow.
    result->entry_point = map_addr;
    
    if ((result->entry_point >= map_addr) && (result->entry_point < (map_addr + map_size))) {
		result->validentry = 1;
    }

	return ret;
}

static
load_return_t
load_uuid(
	struct uuid_command	*uulp,
	char			*command_end,
	load_result_t		*result
)
{
		/*
		 * We need to check the following for this command:
		 * - The command size should be atleast the size of struct uuid_command
		 * - The UUID part of the command should be completely within the mach-o header
		 */

		if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
		    (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
			return (LOAD_BADMACHO);
		}
		
		memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
		return (LOAD_SUCCESS);
}

static
load_return_t
load_main(
	struct entry_point_command	*epc,
	load_result_t		*result
)
{
	mach_vm_offset_t addr;
	
	if (epc->cmdsize < sizeof(*epc))
		return (LOAD_BADMACHO);
	if (result->thread_count != 0) {
		printf("load_main: already have a thread!");
		return (LOAD_FAILURE);
	}

	/* LC_MAIN specifies stack size but not location */
	if (epc->stacksize) {
		result->prog_stack_size = 1;
		result->user_stack_size = epc->stacksize;
	} else {
		result->prog_stack_size = 0;
		result->user_stack_size = MAXSSIZ;
	}
	result->prog_allocated_stack = 0;

	/* The stack slides down from the default location */
	result->user_stack = addr;

	/* kernel does *not* use entryoff from LC_MAIN.	 Dyld uses it. */
	result->needs_dynlinker = TRUE;
	result->validentry = TRUE;

	result->unixproc = TRUE;
	result->thread_count++;

	return(LOAD_SUCCESS);
}


static
load_return_t
load_unixthread(
	struct thread_command	*tcp,
	load_result_t		*result
)
{
    load_return_t	ret;
	int customstack = 0;
	mach_vm_offset_t addr;
	
	if (tcp->cmdsize < sizeof(*tcp))
		return (LOAD_BADMACHO);
	if (result->thread_count != 0) {
		printf("load_unixthread: already have a thread!");
		return (LOAD_FAILURE);
	}
    
    ret = load_threadstack(0,
                (uint32_t *)(((vm_offset_t)tcp) + sizeof(struct thread_command)),
                tcp->cmdsize - sizeof(struct thread_command),
                &addr,
                &customstack);
    if (ret != LOAD_SUCCESS)
        return(ret);

	/* LC_UNIXTHREAD optionally specifies stack size and location */
    
	if (customstack) {
		result->prog_stack_size = 0;	/* unknown */
		result->prog_allocated_stack = 1;
	} else {
		result->prog_allocated_stack = 0;
		result->prog_stack_size = 0;
		result->user_stack_size = MAXSSIZ;
	}

	/* The stack slides down from the default location */
	result->user_stack = addr;

    ret = load_threadentry(0,
                (uint32_t *)(((vm_offset_t)tcp) + sizeof(struct thread_command)),
                tcp->cmdsize - sizeof(struct thread_command),
                &addr);
    if (ret != LOAD_SUCCESS)
        return(ret);
    
    printf("load_unixthread 1: result->entry_point = %p\n", addr);
	result->entry_point = addr;

	result->unixproc = TRUE;
	result->thread_count++;

	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadstate(
	thread_t	thread,
	uint32_t	*ts,
	uint32_t	total_size
)
{
	uint32_t	size;
	int		flavor;
	uint32_t	thread_size;

    
	/*
	 *	Set the new thread state; iterate through the state flavors in
     *  the mach-o file.
	 */
	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		if (UINT32_MAX-2 < size ||
		    UINT32_MAX/sizeof(uint32_t) < size+2)
			return (LOAD_BADMACHO);
		thread_size = (size+2)*sizeof(uint32_t);
		if (thread_size > total_size)
			return(LOAD_BADMACHO);
		total_size -= thread_size;
		/*
		 * Third argument is a kernel space pointer; it gets cast
		 * to the appropriate type in machine_thread_set_state()
		 * based on the value of flavor.
		 */
        
		ts += size;	/* ts is a (uint32_t *) */
	}
	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadstack(
	thread_t	thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*user_stack,
	int *customstack
)
{
	uint32_t	size;
	int		flavor;
	uint32_t	stack_size;

	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
		if (UINT32_MAX-2 < size ||
		    UINT32_MAX/sizeof(uint32_t) < size+2)
			return (LOAD_BADMACHO);
		stack_size = (size+2)*sizeof(uint32_t);
		if (stack_size > total_size)
			return(LOAD_BADMACHO);
		total_size -= stack_size;

		/*
		 * Third argument is a kernel space pointer; it gets cast
		 * to the appropriate type in thread_userstack() based on
		 * the value of flavor.
		 */
        printf("thread_userstack(%d, %d, %p, %d, %p, %p);\n", thread, flavor, (thread_state_t)ts, size, user_stack, customstack);
		/*ret = thread_userstack(thread, flavor, (thread_state_t)ts, size, user_stack, customstack);
		if (ret != KERN_SUCCESS) {
			return(LOAD_FAILURE);
		}*/
		ts += size;	/* ts is a (uint32_t *) */
	}
    
    *user_stack = 7;
    
	return(LOAD_SUCCESS);
}

static
load_return_t
load_threadentry(
	thread_t	thread,
	uint32_t	*ts,
	uint32_t	total_size,
	mach_vm_offset_t	*entry_point
)
{
	uint32_t	size;
	int		flavor;
	uint32_t	entry_size;
    
    mach_vm_offset_t entry_point_save;

	/*
	 *	Set the thread state.
	 */
	*entry_point = MACH_VM_MIN_ADDRESS;
	while (total_size > 0) {
		flavor = *ts++;
		size = *ts++;
        if (UINT32_MAX-2 < size || UINT32_MAX/sizeof(uint32_t) < size+2) {
			return (LOAD_BADMACHO);
        }
        
		entry_size = (size+2)*sizeof(uint32_t);
        if (entry_size > total_size) {
			return(LOAD_BADMACHO);
        }
		
        total_size -= entry_size;
		/*
		 * Third argument is a kernel space pointer; it gets cast
		 * to the appropriate type in thread_entrypoint() based on
		 * the value of flavor.
		 */
        printf("thread_entrypoint(%d, %d, %p, %d, %p);\n", thread, flavor, (thread_state_t)ts, size, entry_point);
		/*ret = thread_entrypoint(thread, flavor, (thread_state_t)ts, size, entry_point);
		if (ret != KERN_SUCCESS) {
			return(LOAD_FAILURE);
		}*/
		ts += size;	/* ts is a (uint32_t *) */
	}
    
    *entry_point = entry_point_save;
    
	return(LOAD_SUCCESS);
}

struct macho_data {
	int	__nid;
	union macho_vnode_header {
		struct mach_header	mach_header;
		struct fat_header	fat_header;
		char	__pad[512];
	} __header;
};

static load_return_t
load_dylinker(
	struct dylinker_command	*lcp,
	integer_t		archbits,
	int			depth,
	int64_t			slide,
	load_result_t		*result
)
{
	char			*name;
	char			*p;
	uint8_t		*vp = NULL;	/* set by get_macho_vnode() */
	struct mach_header	*header;
	off_t			file_offset = 0; /* set by get_macho_vnode() */
	off_t			macho_size = 0;	/* set by get_macho_vnode() */
	load_result_t		*myresult;
	kern_return_t		ret;
	struct macho_data	*macho_data;
	struct {
		struct mach_header	__header;
		load_result_t		__myresult;
		struct macho_data	__macho_data;
	} *dyld_data;

	if (lcp->cmdsize < sizeof(*lcp))
		return (LOAD_BADMACHO);

	name = (char *)lcp + lcp->name.offset;
	/*
	 *	Check for a proper null terminated string.
	 */
	p = name;
	do {
		if (p >= (char *)lcp + lcp->cmdsize)
			return(LOAD_BADMACHO);
	} while (*p++);

	/* Allocate wad-of-data from heap to reduce excessively deep stacks */

    printf("load_dylinker 1: %s\n", name);
    
    dyld_data = malloc(sizeof (*dyld_data));
	header = &dyld_data->__header;
	myresult = &dyld_data->__myresult;
	macho_data = &dyld_data->__macho_data;

	ret = get_macho_vnode(name, archbits, header,
	    &file_offset, &macho_size, macho_data, &vp);
	if (ret)
		goto novp_out;

	*myresult = load_result_null;

	/*
	 *	First try to map dyld in directly.  This should work most of
	 *	the time since there shouldn't normally be something already
	 *	mapped to its address.
	 */

    vp = vp + file_offset;
    file_offset = 0;
    header = (struct mach_header*)vp;
    
	ret = parse_machfile(vp, header, file_offset, macho_size, depth, slide, 0, myresult);

	/*
	 *	If it turned out something was in the way, then we'll take
	 *	take this longer path to preflight dyld's vm ranges, then
	 *	map it at a free location in the address space.
	 */

	if (ret == LOAD_NOSPACE) {
		mach_vm_offset_t	dyl_start, map_addr;
		mach_vm_size_t	dyl_length;
		int64_t			slide_amount;

		*myresult = load_result_null;

		/*
		 * Preflight parsing the Mach-O file with a NULL
		 * map, which will return the ranges needed for a
		 * subsequent map attempt (with a slide) in "myresult"
		 */
		ret = parse_machfile(vp, header,
		                     file_offset, macho_size, depth,
		                     0 /* slide */, 0, myresult);

		if (ret != LOAD_SUCCESS) {
			goto novp_out;
		}

		dyl_start = myresult->min_vm_addr;
		dyl_length = myresult->max_vm_addr - myresult->min_vm_addr;

		dyl_length += slide;

		/* To find an appropriate load address, do a quick allocation */
		map_addr = dyl_start;
        map_addr = (mach_vm_offset_t)malloc(dyl_length);
		if (ret == 0) {
			ret = LOAD_NOSPACE;
			goto novp_out;
		}

        free((void*)map_addr);
		
		if (map_addr < dyl_start)
			slide_amount = -(int64_t)(dyl_start - map_addr);
		else
			slide_amount = (int64_t)(map_addr - dyl_start);

		slide_amount += slide;

		*myresult = load_result_null;

		ret = parse_machfile(vp, header,
		                     file_offset, macho_size, depth,
		                     slide_amount, 0, myresult);

		if (ret) {
			goto novp_out;
		}
	}

	if (ret == LOAD_SUCCESS) {		
		result->dynlinker = TRUE;
		result->entry_point = myresult->entry_point;
		result->validentry = myresult->validentry;
		result->all_image_info_addr = myresult->all_image_info_addr;
		result->all_image_info_size = myresult->all_image_info_size;
	}
    
novp_out:
	free(dyld_data);
	return (ret);

}

#if CONFIG_CODE_DECRYPTION

static load_return_t
set_code_unprotect(
		   struct encryption_info_command *eip,
		   caddr_t addr, 	
		   vm_map_t map,
		   int64_t slide,
		   uint8_t	*vp,
		   cpu_type_t cputype,
		   cpu_subtype_t cpusubtype)
{
	int result, len;
	pager_crypt_info_t crypt_info;
	const char * cryptname = 0;
	char *vpath;
	
	size_t offset;
	struct segment_command_64 *seg64;
	struct segment_command *seg32;
	vm_map_offset_t map_offset, map_size;
	kern_return_t kr;

	if (eip->cmdsize < sizeof(*eip)) return LOAD_BADMACHO;
	
	switch(eip->cryptid) {
		case 0:
			/* not encrypted, just an empty load command */
			return LOAD_SUCCESS;
		case 1:
			cryptname="com.apple.unfree";
			break;
		case 0x10:	
			/* some random cryptid that you could manually put into
			 * your binary if you want NULL */
			cryptname="com.apple.null";
			break;
		default:
			return LOAD_BADMACHO;
	}
	
	if (map == VM_MAP_NULL) return (LOAD_SUCCESS);
	if (NULL == text_crypter_create) return LOAD_FAILURE;

	MALLOC_ZONE(vpath, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if(vpath == NULL) return LOAD_FAILURE;
	
	len = MAXPATHLEN;
	result = vn_getpath(vp, vpath, &len);
	if(result) {
		FREE_ZONE(vpath, MAXPATHLEN, M_NAMEI);
		return LOAD_FAILURE;
	}
	
	/* set up decrypter first */
	crypt_file_data_t crypt_data = {
		.filename = vpath,
		.cputype = cputype,
		.cpusubtype = cpusubtype};
	kr=text_crypter_create(&crypt_info, cryptname, (void*)&crypt_data);
	FREE_ZONE(vpath, MAXPATHLEN, M_NAMEI);
	
	if(kr) {
		printf("set_code_unprotect: unable to create decrypter %s, kr=%d\n",
		       cryptname, kr);
		if (kr == kIOReturnNotPrivileged) {
			/* text encryption returned decryption failure */
			return(LOAD_DECRYPTFAIL);
		 }else
			return LOAD_RESOURCE;
	}
	
	/* this is terrible, but we have to rescan the load commands to find the
	 * virtual address of this encrypted stuff. This code is gonna look like
	 * the dyld source one day... */
	struct mach_header *header = (struct mach_header *)addr;
	size_t mach_header_sz = sizeof(struct mach_header);
	if (header->magic == MH_MAGIC_64 ||
	    header->magic == MH_CIGAM_64) {
	    	mach_header_sz = sizeof(struct mach_header_64);
	}
	offset = mach_header_sz;
	uint32_t ncmds = header->ncmds;
	while (ncmds--) {
		/*
		 *	Get a pointer to the command.
		 */
		struct load_command *lcp = (struct load_command *)(addr + offset);
		offset += lcp->cmdsize;
		
		switch(lcp->cmd) {
			case LC_SEGMENT_64:
				seg64 = (struct segment_command_64 *)lcp;
				if ((seg64->fileoff <= eip->cryptoff) &&
				    (seg64->fileoff+seg64->filesize >= 
				     eip->cryptoff+eip->cryptsize)) {
					map_offset = seg64->vmaddr + eip->cryptoff - seg64->fileoff + slide;
					map_size = eip->cryptsize;
					goto remap_now;
				}
			case LC_SEGMENT:
				seg32 = (struct segment_command *)lcp;
				if ((seg32->fileoff <= eip->cryptoff) &&
				    (seg32->fileoff+seg32->filesize >= 
				     eip->cryptoff+eip->cryptsize)) {
					map_offset = seg32->vmaddr + eip->cryptoff - seg32->fileoff + slide;
					map_size = eip->cryptsize;
					goto remap_now;
				}
		}
	}
	
	/* if we get here, did not find anything */
	return LOAD_BADMACHO;
	
remap_now:
	/* now remap using the decrypter */
	kr = vm_map_apple_protected(map, map_offset, map_offset+map_size, &crypt_info);
	if(kr) {
		printf("set_code_unprotect(): mapping failed with %x\n", kr);
		crypt_info.crypt_end(crypt_info.crypt_ops);
		return LOAD_PROTECT;
	}
	
	return LOAD_SUCCESS;
}

#endif

uint8_t* get_file_data(char* file, int * resulting_size);

/*
 * This routine exists to support the load_dylinker().
 *
 * This routine has its own, separate, understanding of the FAT file format,
 * which is terrifically unfortunate.
 */
static
load_return_t
get_macho_vnode(
	char			*path,
	integer_t		archbits,
	struct mach_header	*mach_header,
	off_t			*file_offset,
	off_t			*macho_size,
	struct macho_data	*data,
	uint8_t		**vpp
)
{
    /*uint8_t* data_f = get_file_data(path, macho_size);
    *vpp = data_f;
    *file_offset = 0;
    *mach_header = *(struct mach_header*)(data_f);
    data->__header.mach_header = *mach_header;
    
    return LOAD_SUCCESS;*/
    
	uint8_t		*vp;
	boolean_t		is_fat;
	struct fat_arch		fat_arch;
	int			error = LOAD_SUCCESS;
	int resid;
	union macho_vnode_header *header = &data->__header;
	off_t fsize = (off_t)0;

	/*
	 * Capture the kernel credential for use in the actual read of the
	 * file, since the user doing the execution may have execute rights
	 * but not read rights, but to exec something, we have to either map
	 * or read it into the new process address space, which requires
	 * read rights.  This is to deal with lack of common credential
	 * serialization code which would treat NOCRED as "serialize 'root'".
	 */

    int file_size;
    vp = get_file_data(path, &file_size);
    
    header = (union macho_vnode_header*)vp;
    
	if (header->mach_header.magic == MH_MAGIC ||
	    header->mach_header.magic == MH_MAGIC_64) {
		is_fat = FALSE;
	} else if (header->fat_header.magic == FAT_MAGIC ||
	    header->fat_header.magic == FAT_CIGAM) {
		is_fat = TRUE;
	} else {
		error = LOAD_BADMACHO;
        printf("get_macho_vnode 1: %s:", load_to_string(error));
		goto bad2;
	}

    printf("Is fat: %d\n", is_fat);
	if (is_fat) {
		/* Look up our architecture in the fat file. */
		error = fatfile_getarch_with_bits(vp, archbits,
		    (vm_offset_t)(&header->fat_header), &fat_arch);
        if (error != LOAD_SUCCESS) {
            printf("get_macho_vnode 2: %s\n", load_to_string(error));
			goto bad2;
        }

        printf("get_macho_vnode 2: fat_arch.offset = %d\n", fat_arch.offset);
        header = (vp + fat_arch.offset);
        
		/* Is this really a Mach-O? */
		if (header->mach_header.magic != MH_MAGIC &&
		    header->mach_header.magic != MH_MAGIC_64) {
			error = LOAD_BADMACHO;
            printf("get_macho_vnode 3: %s\n", load_to_string(error));
			goto bad2;
		}

		*file_offset = fat_arch.offset;
		*macho_size = fat_arch.size;
	} else {
		/*
		 * Force get_macho_vnode() to fail if the architecture bits
		 * do not match the expected architecture bits.  This in
		 * turn causes load_dylinker() to fail for the same reason,
		 * so it ensures the dynamic linker and the binary are in
		 * lock-step.  This is potentially bad, if we ever add to
		 * the CPU_ARCH_* bits any bits that are desirable but not
		 * required, since the dynamic linker might work, but we will
		 * refuse to load it because of this check.
		 */
		if ((cpu_type_t)(header->mach_header.cputype & CPU_ARCH_MASK) != archbits) {
			error = LOAD_BADARCH;
			goto bad2;
		}

		*file_offset = 0;
		*macho_size = fsize;
	}

	*mach_header = header->mach_header;
	*vpp = vp;

    printf("get_macho_vnode 4: %s\n", load_to_string(error));
    
	return (error);

bad2:
bad1:
	return(error);
}

uint8_t* read_fd(int fd) {
    // read the entire file.
    off_t eof = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, 0);
    
    uint8_t* fileArr = mmap(NULL, eof, PROT_READ, MAP_PRIVATE, fd, 0);
    if(fileArr == MAP_FAILED) {
        perror("Unable to map mach-o for reading");
        
        return NULL;
    }
    
    uint8_t* file_buf = (uint8_t*)malloc(eof);
    if(file_buf == NULL) {
        munmap(fileArr, eof);
        perror("Unable to malloc for mach-o buffer");
        
        return NULL;
    }
    
    memcpy(file_buf, fileArr, eof);
    
    munmap(fileArr, eof);
    
    return file_buf;
}

uint8_t* get_file_data(char* file, int * resulting_size) {
    int fd = open(file, O_RDONLY);
    *resulting_size = lseek(fd, 0, SEEK_END);
    
    return read_fd(fd);
}

int main() {
    uint8_t* data;
    load_result_t result;
    struct image_params img;
    int size;
    
    data = get_file_data("/Users/mikhail/play/ios-echo", &size);
    
    printf("Size: %d\n", size);
    
    img.ip_vp = data;
    img.ip_vp_size = size;
    img.ip_arch_offset = 0;
    img.ip_arch_size = size;
    img.ip_vdata = data;
    
    hexdump(data, 100, 0);
    
    load_machfile(&img, data, &result);
    
    return 0;
}
