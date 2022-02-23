/*
 * Written by Devin Schwehr - 11/23/2021

 * This implementation uses an explicit free list implementation
 * with coalescing, block splitting, and block freeing.
 * It also uses a first-fit approach to locate suitable blocks.
 * The explicit free list is ordered in a FILO structuure, where
 * new free blocks are inserted into the beginning of the doubly linked
 * list.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/* always use 16-byte alignment */
#define ALIGNMENT 16

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

/* rounds up to the nearest multiple of mem_pagesize() */
#define PAGE_ALIGN(size) (((size) + (mem_pagesize()-1)) & ~(mem_pagesize()-1))

void *current_avail = NULL;
int current_avail_size = 0;


//MACROS------
// This assumes you have a struct or typedef called "block_header" and "block_footer"
#define OVERHEAD (sizeof(block_header)+sizeof(block_footer))
// Given a payload pointer, get the header or footer pointer
#define HDRP(bp) ((char *)(bp) - sizeof(block_header))
#define FTRP(bp) ((char *)(bp)+GET_SIZE(HDRP(bp))-OVERHEAD)
// Given a payload pointer, get the next or previous payload pointer
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define PREV_BLKP(bp) ((char *)(bp)-GET_SIZE((char *)(bp)-OVERHEAD))
// ******These macros assume you are using a size_t for headers and footers ******
// Given a pointer to a header, get or set its value
#define GET(p) (*(size_t *)(p))
#define PUT(p, val) (*(size_t *)(p) = (val))
// Combine a size and alloc bit
#define PACK(size, alloc) ((size) | (alloc))
// Given a header pointer, get the alloc or size
#define GET_ALLOC(p) (GET(p) & 0x1)
#define GET_SIZE(p) (GET(p) & ~0xF)

#define WSIZE 8   //Word and header/footer size
#define DSIZE 16   //Size of Double word
#define CHUNKSIZE (1<<12)   //Extend heap by this amount in bytes

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define GET_NODE(p) ((mem_node*)(p))

//STRUCTS-----

// **************************************************************************
// *****
// ******Recommended helper functions******

/* These functions will provide a high-level recommended structure to your 
program.
* Fill them in as needed, and create additional helper functions 
depending on your design.
*/

/* Set a block to allocated
* Update block headers/footers as needed
* Update free list if applicable
* Split block if applicable
*/
static void set_allocated(void *b, size_t size);

/* Request more memory by calling mem_map
* Initialize the new chunk of memory as applicable
* Update free list if applicable
*/
static void extend(size_t s);

/* Coalesce a free block if applicable
* Returns pointer to new coalesced block
*/
static void* coalesce(void *bp);

/*
* This function is to check the construction of the doubly linked list
*/
static void check();

/*
* This function handles inserting nodes into the explicit free list
*/
static void free_list_insert(void *p);

/*
*This function handles removing nodes from the explicit free list
*/
static void free_list_remove(void *p);


typedef struct block_header {
  size_t size;
}block_header;

typedef struct block_footer {
  size_t size;
}block_footer;

typedef struct mem_node {
  struct mem_node *prev;
  struct mem_node *next;
}mem_node;


static void *list_pointer;
static void *tail_pointer;

static mem_node *explicit_free_list;

size_t mem_chunk;

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{

  // Initialize the implicit list to be empty
  list_pointer = NULL;
  mem_chunk = 7*mem_pagesize();
  explicit_free_list = NULL;

  return 0;

}

/* 
 * mm_malloc - Allocate a block by using bytes from current_avail,
 *     grabbing a new page if necessary.
 */
void *mm_malloc(size_t size)
{
  if(size == 0) {return NULL;}  //Return if size is not valid

  if(size <= 16) {size = 16;}

  int newsize = ALIGN(size)+(DSIZE); //align the size and add padding for header/footer
  void *p;

  p = explicit_free_list;
  size_t pointer_size;
  while(p != NULL)
  {
    //Get the size of the block
    pointer_size = GET_SIZE(HDRP(p));
    //If we found a block that fits, allocate it and return
    if(pointer_size >= newsize)
    {
      set_allocated(p,newsize);
      return p;
    }
    //Otherwise, just continue forward
    p = GET_NODE(p)->next;
  }
  //If we could not find a block that fits, then extend to fit new block
  extend(newsize);
  //p should now point to the newly created block
  p = explicit_free_list;
  set_allocated(p,newsize);
  return p;
  
}

/*
 * mm_free - Freeing a block sets its allocation status to 0. Also looks to coalesce if possible.
 */
void mm_free(void *ptr)
{
  size_t ptr_size = GET_SIZE(HDRP(ptr));
  PUT(HDRP(ptr),PACK(ptr_size,0));
  PUT(FTRP(ptr),PACK(ptr_size,0));

  free_list_insert(ptr);
  coalesce(ptr);
}


// **************************************************************************
// *****
// ******Recommended helper functions******

/* These functions will provide a high-level recommended structure to your 
program.
* Fill them in as needed, and create additional helper functions 
depending on your design.
*/

/* Set a block to allocated
* Update block headers/footers as needed
* Update free list if applicable
* Split block if applicable
*/
static void set_allocated(void *b, size_t size)
{
  free_list_remove(b);

  void* header = HDRP(b);
  size_t second_size;

  second_size = GET_SIZE(header) - size;

  //this is if the size is exact or needs padding to fit
  if(second_size < 48)
  {
    PUT(HDRP(b),PACK(GET_SIZE(header),1));
    PUT(FTRP(b),PACK(GET_SIZE(header),1));
    return;
  }
  
  //Otherwise, we can split the block up
    PUT(header,PACK(size,1));
    PUT(FTRP(b),PACK(size,1));

  //Get the next block to put the remaining data in
  void *next_b = NEXT_BLKP(b);

  PUT(HDRP(next_b),PACK(second_size,0));
  PUT(FTRP(next_b),PACK(second_size,0));

  free_list_insert(next_b);

  return;

}

/* Request more memory by calling mem_map
* Initialize the new chunk of memory as applicable
* Update free list if applicable
*/
static void extend(size_t s)
{
  void *bp;

  //If the current mem chunk size is smaller than the size requested
  if(mem_chunk < s)
  {
    mem_chunk = 6*PAGE_ALIGN(s+((2*DSIZE)));
  }

  //Get a new block of 4096 bytes.
  bp = mem_map(mem_chunk);

  PUT(bp+(WSIZE), PACK(2*(WSIZE),1));  //Prologue Header space
  PUT(bp+(2*WSIZE), PACK(2*(WSIZE),1));  //Prologue Footer space

  PUT(bp + mem_chunk - 8, PACK(0,1)); //Epilogue Header at end of page

  PUT(bp+(3*WSIZE),PACK(mem_chunk-(2*DSIZE),0)); //Create the block
  //Put the pointer at the start of the payload
  bp += 4*WSIZE;

  PUT(FTRP(bp),PACK(mem_chunk-(DSIZE*2), 0)); //Block Footer

  //Now we add this new block to our explicit free list
  free_list_insert(bp);

  return;

}

/* Coalesce a free block if applicable
* Returns pointer to new coalesced block
*/
static void* coalesce(void *bp)
{
  //Before we begin, we must get the next and previous block and their allocation statuses
  void *prev_b = PREV_BLKP(bp);
  size_t prev_alloc = GET_ALLOC(FTRP(prev_b));
  void *next_b = NEXT_BLKP(bp);
  size_t next_alloc = GET_ALLOC(HDRP(next_b));

  //Now we get the size of the current block
  size_t size = GET_SIZE(HDRP(bp));

  //Now we begin the 4 cases, starting with the case of both the next and prev being allocated
  if(prev_alloc && next_alloc) {return bp;}
  
  //The next block is free
  if(prev_alloc && !next_alloc)
  {
    //We will remove the current and next block from the list
    free_list_remove(bp);
    free_list_remove(next_b);

    //Increment the size to incorporate the next block, and then insert the new larger block
    size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
    PUT(HDRP(bp), PACK(size,0));
    PUT(FTRP(bp), PACK(size,0));

    free_list_insert(bp);
  }
  //the prev block is free
  else if(!prev_alloc && next_alloc)
  {
    free_list_remove(bp);
    free_list_remove(prev_b);

    size+= GET_SIZE(HDRP(PREV_BLKP(bp)));
    PUT(FTRP(bp), PACK(size,0));  //Expand the footer with the new size
    PUT(HDRP(PREV_BLKP(bp)),PACK(size,0));  //Expand prev block header with new size
    bp = PREV_BLKP(bp); //Set block to previous block

    free_list_insert(bp);
  }
  //Both blocks are free
  else
  {
    free_list_remove(bp);
    free_list_remove(prev_b);
    free_list_remove(next_b);

    size += (GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp))));  //Add sizes of prev and next
    //Update the prev block header and next block's footer
    PUT(HDRP(PREV_BLKP(bp)), PACK(size,0));
    PUT(FTRP(NEXT_BLKP(bp)),PACK(size,0));
    bp = PREV_BLKP(bp);

    free_list_insert(bp);
  }

  //If none of the other cases apply, then we know that we have encountered a chunk
  if(GET_SIZE(HDRP(bp)) > 8*mem_pagesize() && GET_SIZE(HDRP(PREV_BLKP(bp))) == 16 && GET_SIZE(HDRP(NEXT_BLKP(bp))) == 0)
  {
    void *s = bp - 32;
    size_t c_size = GET_SIZE(HDRP(bp)) + 32;
    free_list_remove(bp);
    mem_unmap(s,c_size);
  }
  return bp;
}

static void free_list_insert(void *p)
{
  mem_node *node = GET_NODE(p);
  if(explicit_free_list == NULL) //Case where our list is empty
  {
    //Insert the lone block into the list. The list points to this lone node.
    node->next = NULL;
    node->prev = NULL;
    explicit_free_list = node;
  } 
  else  //Otherwise our list is not empty, insert it into the list
  {
    //Follows a FILO approach, inserting the node at the beginning of our list, and updating the reference to point to this new block
    node->next = explicit_free_list;
    node->prev = NULL;
    explicit_free_list->prev = node;
    explicit_free_list = node;
  }
}

/*
*This function removes a block pointer from the explicit free list.
*/
static void free_list_remove(void *p)
{
  mem_node *node = GET_NODE(p);

  //4 cases:

  //If only element, just set the entire list to null. It will be filled again later in insert.
  if(node->prev == NULL && node->next == NULL)
  {
    explicit_free_list = NULL;
    return;
  }
  //Head node?
  else if(node->prev == NULL)
  {
    //Update the head reference
    explicit_free_list = node->next;
    explicit_free_list->prev = NULL;

    node = NULL;
  }
  //Opposite case, tail is null?
  else if(node->next == NULL)
  {
    //Have the node behind this one point to null
    node->prev->next = NULL;
    node = NULL;
  }
  //Last case, node is in the middle of the list
  else
  {
    node->prev->next = node->next;  //Set node behind to point to node forward
    node->next->prev = node->prev;  //Set node forward to point to node behind
    node = NULL;
  }
}

/*
*This was a basic heap checker that I was using for checking my implicit list early on in development.
*/
static void check()
{
  //We will increment along our list and make sure that we are pointing to the proper things

  //make sure that head's prev and tail's next are null
  if(PREV_BLKP(list_pointer) != NULL || PREV_BLKP(list_pointer) != 0)
  {
    printf("Error! list_pointer's prev is not null");
  }
  if(NEXT_BLKP(tail_pointer) != NULL)
  {
    printf("Error! tail's next is not NULL");
  }

  void *current_block;
  current_block = list_pointer;

  while(HDRP(NEXT_BLKP(current_block))!= tail_pointer)
  {
    if(NEXT_BLKP(current_block) != PREV_BLKP(NEXT_BLKP(current_block)))
    {
      printf("Error! mismatch between current block pointing forward and next block pointing backward");
      break;
    }
    current_block = NEXT_BLKP(current_block);
  }
  printf("Heap check successful");
}