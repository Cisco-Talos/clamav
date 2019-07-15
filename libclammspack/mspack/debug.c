/* random debugging routines for cut'n'paste when developing */

static char *binary(unsigned int val, unsigned int bits) {
  static char data[33] = "";
  char *ptr = &data[bits];
  if (bits > 32) return "bits>32";
  *ptr-- = '\0'; 
  while (bits--) { *ptr-- = (val & 1) ? '1' : '0'; val >>= 1; }
  return &data[0];
}

static void cabinfo(struct mscabd_cabinet_p *cab) {
  struct mscabd_folder_data *dat;
  struct mscabd_folder_p *fol;
  struct mscabd_file *fi;

  printf("cab@%p\n", cab);
  if (!cab) return;
  printf("- next=%p\n", cab->base.next);
  printf("- filename=\"%s\"\n", cab->base.filename);
  printf("- base_offset=%ld\n", cab->base.base_offset);
  printf("- length=%ld\n", cab->base.length);
  printf("- prevcab=%p\n", cab->base.prevcab);
  printf("- nextcab=%p\n", cab->base.nextcab);
  printf("- prevname=\"%s\"\n", cab->base.nextname);
  printf("- previnfo=\"%s\"\n", cab->base.nextinfo);
  printf("- nextname=\"%s\"\n", cab->base.nextname);
  printf("- nextinfo=\"%s\"\n", cab->base.nextinfo);
  printf("- flags=0x%x\n", cab->base.flags);
  printf("- folders:\n");
  for (fol = cab->folders; fol; fol = fol->next) {
    printf("  folder@%p\n", fol);
    printf("  - comp_type=0x%x\n", fol->comp_type);
    printf("  - merge_prev=%p\n", fol->merge_prev);
    printf("  - merge_next=%p\n", fol->merge_next);
    for (dat = &fol->data; dat; dat=dat->next) {
      printf("  - datasplit@%p = CAB(%p) OFFSET(%ld) BLOCKS(%d)\n",
             dat, dat->cab, dat->offset, dat->num_blocks);
    }
  }
  printf("- files:\n");
  for (fi = cab->base.files; fi; fi = fi->next) {
    printf("  @%p \"%s\" %d FOL(%p) OFFSET(%u)\n",
           fi, fi->filename, fi->length,
           ((struct mscabd_file_p *) fi)->folder,
           ((struct mscabd_file_p *) fi)->offset);
  }
}


