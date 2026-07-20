---
title: A Linux Kernel 0-day Journey - From a limited UAF to Physical Memory R/W
date: 2026-07-20
author: kiks
---
## Introduction
This article is related to a Linux Kernel 0-day I have recently found and exploited initially for Pwn2own 2026 (Red Hat category). Unfortunately, I waited too long to register (even if it was before the deadline) and ended up being ignored (legitimately due to the unexpected number of submissions) and so, I was not able to participate. The bug ended up being reported from another researcher, but no public details (and no CVE) have been still published about it and on its exploitability.
The bug is *just another bug* in the network scheduler subsystem, the red scheduler. I have picked this subsystem as a target for three main reasons: unprivileged user namespaces are enabled in Red Hat, schedulers are an historically interesting subsystem (due to the high complexity and interactions with multiple network parts) and I had a fuzzer suitable for that kind of targets (syzkaller has its own limitations with this type of subsystems).
Besides of the bug, the most interesting part is the exploitation strategy, turning an initially limited slab UAF into a page UAF and ultimately into a physical memory read and write.

## The bug
The vulnerability affects the "red network scheduler" (what a *coincidence* since I was targeting Red Hat) and has been introduced in commit [3f14b37](https://github.com/torvalds/linux/commit/3f14b377d01d8357eba032b4cabc8c1149b458b6) (January 2024) and fixed in commit [a8a0289](https://github.com/torvalds/linux/commit/a8a02897f2b479127db261de05cbf0c28b98d159) (June 2026), lasting for 2.5 years. The fix is really straightforward and immediate:

```diff
--- a/net/sched/cls_api.c
+++ b/net/sched/cls_api.c
@@ -4049,6 +4049,9 @@ struct sk_buff *tcf_qevent_handle(struct tcf_qevent *qe, struct Qdisc *sch, stru
 		skb_do_redirect(skb);
 		*ret = __NET_XMIT_STOLEN;
 		return NULL;
+	case TC_ACT_CONSUMED:
+		*ret = __NET_XMIT_STOLEN;
+		return NULL;
 	}
 
 	return skb;
```

I couldn't explain any better than what has been already done in the commit, so I'm just gonna extract the key part from it and add more details on top:

```plain
tcf_classify() can return TC_ACT_CONSUMED while the skb is held by the
defragmentation engine (e.g. act_ct on out-of-order fragments). When
that happens the skb is no longer owned by the caller and must not be
touched again.

tcf_qevent_handle() did not handle TC_ACT_CONSUMED: it fell through the
switch and returned the skb to the caller as if classification had
passed.
```

To see it in practice through the code, the red enqueue function ([`red_enqueue`](https://elixir.bootlin.com/linux/v6.12.83/source/net/sched/sch_red.c#L70)) is responsible to enqueue packets on its own scheduler. 
```C
static int red_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	switch (red_action(&q->parms, &q->vars, q->vars.qavg)) { // [2]
	case RED_DONT_MARK:
		break;

	case RED_PROB_MARK:
		// ..
		if (INET_ECN_set_ce(skb)) {
			q->stats.prob_mark++;
			skb = tcf_qevent_handle(&q->qe_mark, sch, skb, to_free, &ret); // [1]
			if (!skb)
				return NET_XMIT_CN | ret;
			// ..
		/* Non-ECT packet in ECN nodrop mode: queue it. */
		break;
	case RED_HARD_MARK:
		// ..
		if (INET_ECN_set_ce(skb)) {
			q->stats.forced_mark++;
			skb = tcf_qevent_handle(&q->qe_mark, sch, skb, to_free, &ret); // [1]
			if (!skb)
				return NET_XMIT_CN | ret;
		// ..
	}
	// ..
	ret = qdisc_enqueue(skb, child, to_free); // [5]
	// ..
}

```

The `tcf_qevent_handle` [1] function is called in multiple locations when [`red_action`](https://elixir.bootlin.com/linux/v6.12.83/source/include/net/red.h#L414) [2] returns `RED_PROB_MARK` or `RED_HARD_MARK` (basically when an user-controllable threshold is reached). When one of the two values is returned, and ECN is set (configurable from the `tc` command line), [`tcf_qevent_handle`](https://elixir.bootlin.com/linux/v6.12.83/source/net/sched/cls_api.c#L4015) is called:

```C
struct sk_buff *tcf_qevent_handle(struct tcf_qevent *qe, struct Qdisc *sch, struct sk_buff *skb,
				  struct sk_buff **to_free, int *ret)
{
	// ..
	switch (tcf_classify(skb, NULL, fl, &cl_res, false)) { // [3]
	case TC_ACT_SHOT:
		qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		*ret = __NET_XMIT_BYPASS;
		return NULL;
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
	case TC_ACT_TRAP:
		__qdisc_drop(skb, to_free);
		*ret = __NET_XMIT_STOLEN;
		return NULL;
	case TC_ACT_REDIRECT:
		skb_do_redirect(skb);
		*ret = __NET_XMIT_STOLEN;
		return NULL;
	}

	return skb;
}

// called from tcf_classify after few dereferences
TC_INDIRECT_SCOPE int tcf_ct_act(struct sk_buff *skb, const struct tc_action *a,
				 struct tcf_result *res)
{
	// ..
	err = tcf_ct_handle_fragments(net, skb, family, p->zone, &defrag);
	if (err)
		goto out_frag;

	// ..
out_frag:
	if (err != -EINPROGRESS)
		tcf_action_inc_drop_qstats(&c->common);
	return TC_ACT_CONSUMED; // [4]
}

```

This is where the bug lives, and is simply a missing `case` for the `TC_ACT_CONSUMED` value that can be returned from `tcf_classify` [3]. This value can be returned in multiple user controllable scenarios (e.g. when a fragmented packet is sent) and basically means that the ownership is transferred to the skb defragmentation engine, and the caller has to drop it. 
[`tcf_ct_act`](https://elixir.bootlin.com/linux/v6.1.83/source/net/sched/act_ct.c#L1104) is called (after few dereferences) from `tcf_classify` and returns `TC_ACT_CONSUMED` [4] when [`tcf_ct_handle_fragments`](https://elixir.bootlin.com/linux/v6.1.83/source/net/sched/act_ct.c#L845) returns something, that is the case for a first fragmented packet sent. However, the switch condition in  `tcf_qevent_handle` ignores the `TC_ACT_CONSUMED` case and fallthrough into returning the `skb` instead of `NULL` , ultimately ending up into enqueueing the packet in the scheduler queue [5] with [`qdisc_enqueue`](https://elixir.bootlin.com/linux/v6.12.83/source/include/net/sch_generic.h#L893), indirectly calling [`bfifo_enqueue`](https://elixir.bootlin.com/linux/v6.12.83/source/net/sched/sch_fifo.c#L19) that will store the `skb` pointer (still not freed) as the last element of its queue [6] using the `skb->next` list.

```C
static int bfifo_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			 struct sk_buff **to_free)
{
	if (likely(sch->qstats.backlog + qdisc_pkt_len(skb) <=
		   READ_ONCE(sch->limit)))
		return qdisc_enqueue_tail(skb, sch);

	return qdisc_drop(skb, sch, to_free);
}

static inline int qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch)
{
	__qdisc_enqueue_tail(skb, &sch->q);
	qdisc_qstats_backlog_inc(sch, skb);
	return NET_XMIT_SUCCESS;
}

static inline void __qdisc_enqueue_tail(struct sk_buff *skb,
					struct qdisc_skb_head *qh)
{
	struct sk_buff *last = qh->tail;

	if (last) {
		skb->next = NULL;
		last->next = skb; // [6]
		qh->tail = skb;
	} else {
		qh->tail = skb;
		qh->head = skb;
	}
	qh->qlen++;
}
```

The `skb` pointer here is still not freed, but it will be just when the second fragmented packet arrives, leaving the dangling pointer as the last element of the queue. To be more precise, it will be freed in [`inet_frag_reasm_prepare`](https://elixir.bootlin.com/linux/v6.12.83/source/net/ipv4/inet_fragment.c#L450) with a [`consume_skb`](https://elixir.bootlin.com/linux/v6.12.83/source/net/ipv4/inet_fragment.c#L494) call (always starting from the `tcf_classify` call).

## The primitives
A first primitive might be already spotted from the shown code:
```C
static inline void __qdisc_enqueue_tail(struct sk_buff *skb,
					struct qdisc_skb_head *qh)
{
	struct sk_buff *last = qh->tail; // [7]

	if (last) {
		skb->next = NULL;
		last->next = skb; // [6]
		qh->tail = skb;   // [8]
	} else {
		qh->tail = skb;
		qh->head = skb;
	}
	qh->qlen++;
}
```

As we said, when the `skb` is erroneously inserted in the queue, it is still allocated but the ownership has been transferred. When the second fragment arrives, the `skb` is freed leaving a dangling pointer in the tail of the queue (`qh->tail` [7]), that is stored in the `last` variable and will lead to the primitive at [8] : **a pointer write**. 

In the `qh->tail = skb` line [8], `qh->tail` is a dangling pointer and, most importantly, we can make `skb` a dangling pointer too by using the same technique as before. And here there is an interesting detail from an exploitation point of view. When sending two fragmented packets, the first one's length is set to 0, while the second one carries the summed size of both packets. Why does this matter? Because, if you closely look at the if condition in [`bfifo_enqueue`](https://elixir.bootlin.com/linux/v6.12.83/source/net/sched/sch_fifo.c#L19), packets are only enqueued if they do not exceed the scheduler limit (adjustable from user-space), meaning that we can deterministically place a pointer that we can then free with same bug primitive (e.g. the first fragments of the two), leading to a more interesting **freed pointer write** at offset 0 ([`next`](https://elixir.bootlin.com/linux/v6.12.83/source/include/linux/skbuff.h#L870) offset from the [`sk_buff`](https://elixir.bootlin.com/linux/v6.12.83/source/include/linux/skbuff.h#L756) struct).

This is not the only primitive this bug offers. Another pretty powerful primitive come from the `red_dequeue` function (responsible to dequeue enqueued packets) and will be mentioned in the dedicated "Some notes on AI exploit development and the other primitive" chapter, with the reasons that led me choose this one instead.

## The exploit
### First assessment
At this point I had a pretty limited UAF primitive and one and an half week until the pwn2own registration deadline, I had to make it quick. I spent some time in finding the most interesting object I could reallocate with a Cross Cache, overwrite the first 8 bytes, and exploit its side effects, wether another pointer, a size value (considering the big `0xffff...` semi *controlled* value), a refcount or something similar. The only Cross Cache constraint is that the dangling pointer starts from an order 1 (2 pages) cache `skbuff_head_cache` (*in systems with 4 cores or more*).
### First stage: from slab UAF to page UAF
At some point I remembered about a [public exploit](https://ssd-disclosure.com/lpe-via-refcount-imbalance-in-the-af_unix-of-ubuntus-kernel/) that was targeting exactly `sk_buff`, and this is where I stumbled into the [`pgv` struct](https://elixir.bootlin.com/linux/v6.12.83/source/net/packet/internal.h#L55), even if it was not using it like I would.

```C
static int
packet_setsockopt(struct socket *sock, int level, int optname, sockptr_t optval,
		  unsigned int optlen)
{
	// ..
	switch (optname) {
	case PACKET_RX_RING:
	case PACKET_TX_RING: // [9]
	{
		// ..
		case TPACKET_V3:
		// ..
		if (!ret)
			ret = packet_set_ring(sk, &req_u, 0,
					      optname == PACKET_TX_RING);
		release_sock(sk);
		return ret;
	}
	// ..
}

static int packet_set_ring(struct sock *sk, union tpacket_req_u *req_u,
		int closing, int tx_ring)
{
	// ..
	if (req->tp_block_nr) {
		// ..
		order = get_order(req->tp_block_size);
		pg_vec = alloc_pg_vec(req, order);
		// ..
	}
	// ..
}

tatic struct pgv *alloc_pg_vec(struct tpacket_req *req, int order)
{
	unsigned int block_nr = req->tp_block_nr;
	struct pgv *pg_vec;
	int i;

	pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN); // [10]
	// ..

	for (i = 0; i < block_nr; i++) {
		pg_vec[i].buffer = alloc_one_pg_vec_page(order); // [11]
		if (unlikely(!pg_vec[i].buffer))
			goto out_free_pgvec;
	}
out:
	return pg_vec;
	// ..
}

static char *alloc_one_pg_vec_page(unsigned long order)
{
	// ..
	buffer = (char *) __get_free_pages(gfp_flags, order); // [12]
	// ..
}
```

The `pgv` struct is incredibly interesting for its flexibility, but most importantly for its content. It can be allocated with a `setsockopt` syscall with [`PACKET_TX_RING`](https://elixir.bootlin.com/linux/v6.12.83/source/net/packet/af_packet.c#L3866) [9] parameter, and it will allocate a user-controllable size object into an arbitrary generic cache (e.g. `kmalloc-XXXX`) given the user-controllable size specified in `block_nr` [10]. This allocation will be filled with page pointers [11] (allocated from  `__get_free_pages` [12]) with the `order` value controllable from the user too.
Since we can overwrite a pointer at offset 0, what's better than a list of page pointers?

Before diving into the reallocation of the second object, let's see what primitives gives us the corruption of one of the `pgv` pointers with a dangling pointer.

At first, I went down a rabbit hole that costed me an entire day and a bit more. It is possible, given an allocated `pgv`, to map it through the [`packet_mmap`](https://elixir.bootlin.com/linux/v6.12.83/source/net/packet/af_packet.c#L4621) file operation.

```C
static int packet_mmap(struct file *file, struct socket *sock,
		struct vm_area_struct *vma)
{
	// ..
	for (rb = &po->rx_ring; rb <= &po->tx_ring; rb++) {
		// ..

		for (i = 0; i < rb->pg_vec_len; i++) {
			void *kaddr = rb->pg_vec[i].buffer;
			// ..

			for (pg_num = 0; pg_num < rb->pg_vec_pages; pg_num++) {
				page = pgv_to_page(kaddr);
				err = vm_insert_page(vma, start, page); // [13]
				// ..
			}
		}
	}
	// ..
}

static int insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page, pgprot_t prot)
{
	// ..
	retval = validate_page_before_insert(vma, page);
	if (retval)
		goto out;
	retval = -ENOMEM;
	pte = get_locked_pte(vma->vm_mm, addr, &ptl);
	if (!pte)
		goto out;
	retval = insert_page_into_pte_locked(vma, pte, addr, page, prot);
	pte_unmap_unlock(pte, ptl);
out:
	return retval;
}
static int validate_page_before_insert(struct vm_area_struct *vma,
				       struct page *page)
{
	struct folio *folio = page_folio(page);
	// ..
	if (folio_test_anon(folio) || folio_test_slab(folio) ||
	    page_has_type(page))
		return -EINVAL;
	flush_dcache_folio(folio);
	return 0;
}
```

As can be seen from the code, by calling `mmap` on that file descriptor, the `mmap` handler iterates over the just allocated `pgv` pointers and calls `vm_insert_page` [13] on each of them. Considering that we "control" one pointer, it might means that we can map to user-space an arbitrary pointer. And that's true, but not the entire truth.

First, [`pgv_to_page`](https://elixir.bootlin.com/linux/v6.12.83/source/net/packet/af_packet.c#L393) calls `virt_to_page` and does a big favor to us by page aligning the pointer (considering that we have replaced a page aligned pointer with a slab pointer that might not be page aligned) and then calls `vm_insert_page` on it. At first, the idea was trying to map some arbitrary memory to user-space (e.g. an entire slab page, a read-only memory or file, ..) but this is not permitted due to sanity checks in [`validate_page_before_insert`](https://elixir.bootlin.com/linux/v6.12.83/source/mm/memory.c#L2023) that validates that the pointer is not part of a slab and is not anonymous (e.g. is not file backed). I still think that something interesting can be done with this primitive, but it was taking too much time, the deadline was approaching and I had to make it somehow.

Looking at other parts of the `pgv` code, I found another interesting primitive in the freeing process of the `pgv` pointers. While closing the socket file descriptor associated with the allocated `pgv` object, [`free_pg_vec`](https://elixir.bootlin.com/linux/v6.12.83/source/net/packet/af_packet.c#L4386)  iterates over each pointer and calls `free_pages` on each of them, permitting us to free our second dangling pointer again, but now with `free_pages`. This upgrades our primitive to a more powerful **page-level UAF**. And, similarly to the previous case, the pointer is page aligned directly inside the called free function.

However, the time spent on the `mmap` path did not ended up as an entire waste of time, even if it was not chosen as the final primitive. It has been used in the exploit to verify which `pgv` allocation was containing the second dangling pointer instead of a legitimate pointer by mapping it with `mmap` and verifying if it succeed or not. If the `mmap` call fails, it means that `vm_insert_page` has failed and we obtain two useful information: the first stage has been successful and we know precisely which allocation has been corrupted!

### Second stage: from page UAF to physical memory r/w
Once the first dangling pointer is cross cached into a `pgv` object (I deliberately avoid details about cross cache, spraying and similar since these are well known techniques), we trigger the bug a second time to store the second dangling pointer at offset zero of the first cross cached dangling pointer (the `pgv` object). We then proceed to drain the `skbuff_head_cache` in order to move the second dangling pointer to the order 1 page per-cpu freelist, with the objective to exploit the just created page-level UAF.

At this point I was trying multiple sprays to reclaim the page pointer with something interesting, and while I was spraying some anonymous regions, I found the holy grail from the gdb dump:

```
0x8000000114d1c067 0x8000000114d1c077
0x8000000114d1c087 0x8000000114d1c097
```

Look familiars? these are PTEs!

*Side note: you might be wondering how I was able to reclaim an order 1 allocation with an order-0 PTE allocation with just some "random" spray. Well, that's because at first I was writing the exploit in a 2 core qemu environment where 256-bytes slabs are order-0, the case of skbuff_head_cache. However, on systems with 4 or more cores, these slabs are order-1 and the exploit was targeting that configuration.*

I was immediately caught from that memory content, corrupting PTEs is an amazing primitive to ultimately achieve physical memory read and write.

However, as mentioned, I was first writing the exploit against a qemu environment with 2 cores, making the `skbuff_head_cache` an order-0 cache instead of an order-1 (the pwn2own setup could be likely with more than 4 cores). This made me restructure the page reclamation process with some more shaping. At first, the second dangling pointer is drained from the `skbuff_head_cache` to the order-1 page per-cpu freelist. Then, in order to reallocate it as an order-0 allocation, the pointer must leave the page per-cpu freelist and be inserted into the order-1 buddy freelist, permitting it to be splitted into two order 0 allocations (hence reclaimed as a PTE). I have accomplished that by using multiple `pgv` allocations to spray and shape the page freelists. Then, PTEs have been sprayed through anonymous memory using `mmap`, and the order-1 allocation has been successfully reclaimed from two order-0 allocations.

### Third stage: arbitrary physical memory read and write 
Once the second dangling pointer is reclaimed as a PTE, we can trigger the `free_page` on it and reallocate with something more controllable from user-space. The [`msg_msgseg`](https://elixir.bootlin.com/linux/v6.12.83/source/ipc/msgutil.c#L37) object seemed a reasonable choice due to its high-level of control on content and lifetime from user-space (except for the first `next` pointer that will be NULL for order-0 allocations but that will not be a problem), even better than [`msg_msg`](https://elixir.bootlin.com/linux/v6.12.83/source/include/linux/msg.h#L9). Another key aspect of this target object is that it will be allocated into a `kmalloc-` cache, making it easily readable and writable from user-space (considering the `usercopy` mitigation).

At first, messages are sprayed with a leaked physical address (converted as PTE) from `/sys/kernel/vmcoreinfo` (readable from unprivileged users on all major distributions), to start with a valid physical address. To find the sprayed map that corresponds to the ovewritten PTEs, it is just necessary to verify the content of each mapped memory. Once the userland mapping has been found, in order to write new PTEs for the arbitrary physical read and write, we can receive and send all sprayed messages (`msg_msgseg` objects) one by one, to avoid the slab reallocation of different objects or even cache. During this process, it is also possible to find the correctly reallocated messages to optimize further PTEs modifications and have more stability.

### Fourth stage: uid=0
At this point, it was two days before the registration deadline, I was really excited to have made it and I just needed the lasts, easier steps. I sent the registration e-mail and took a day off, with the idea of coming back once I got the registration and enjoy the engineering process of transforming the physical memory read and write to root.
However, I didn't received any response the next day, neither in the deadline day, and neither later. Since I had a lot of other work to do, I just finished with this primitive.

However, going from that really powerful primitive to root is just a matter of playing with it a bit. My first ideas were to scan memory starting from the `vmcoreinfo` leak (a dynamically allocated object, not part of any static kernel address), find a valid kernel address to break physical address randomization (enabled in Red Hat), and then overwrite the `task_struct` of the current process starting from the `init_struct`, or something similar. Unfortunately, I did not have the pleasure of doing that due to other pending projects with higher priority.

## Some notes on AI exploit development and the other primitive
During the exploitation process of this bug, since it could be considered a short-living bug given the pwn2own participation, I gave a try on using a public frontier model to write a full exploit: Opus 4.8 with Max Pro plan using Claude Code. I was surprised in both good and bad senses.

The good part is that it effectively wrote a working exploit, using an alternative primitive from the [`red_dequeue`](https://elixir.bootlin.com/linux/v6.1.83/source/net/sched/sch_red.c#L150) code that permits to redirect execution and achieve a ROP chain from the `sk_buff` destructor. It was using a side channel for KASLR leak and pwn2own rules consider using it as a partial win, so I wanted something more self-contained with the same bug. I run multiple sessions with qemu and debugging capabilities given to the agent, but it was not able to find a valid KASLR leak from that primitive.

The bad part instead is that it was not able to assist me much during the exploitation that I have explained in this article. I tried to redirect its thoughts with my ideas, giving some hints and some new paths, but after hours of background working, it was continuously falling back to the side-channel leak and ROP. At some point I was also doubting that my ideas would even work considering the continuous gaslighting from the model, but I had a sense that this bug could be more powerful and self-contained than what the model was saying. And, I was right.

That said, this is just my experience, these model are extremely powerful and are continuously improving, as public [articles](https://www.hacktron.ai/blog/watching-gpt-55-sol-ultra-write-a-chrome-exploit-exploit-development-as-we-know-it-is-over) show in the exploit development field, and a lot depends on how you use them, how many tokens and so many other factors.

*Also, no AI has been involved in writing this article. I found it pretty boring to find AI patterns in content mainly written for humans, that I prefer to see an imperfect, but personal and human recognizable, style of writing. If you see some errors, just ping me on [X](https://x.com/kiks7_7) like it used to.*

### Conclusions
I have not talked too much about spraying details, stabilization and reliability improvements, even if they were roughly 60-70% of the work. I wanted to focus more on general ideas of the exploitation strategy and bug root cause. I don't have plans to publish the exploit soon since the vulnerability is still pretty fresh, and there is also no CVE assigned at the moment of writing.

About the pwn2own failed registration, I was [not](https://x.com/terrynini38514/status/2052212654979367128?s=20) [the](https://x.com/_jsoo_/status/2052215335655440683?s=20) [only](https://x.com/v_metnew/status/2053142392132325407?s=20) one with that experience, and I don't blame the organization. It was unfortunate and I was really excited to participate on it, considering that I have also posted about a [failed attempt](https://1day.dev/posts/not-all-roads-lead-to-pwn2own-hardware-hacking-part-1.html) few years ago with [Hacktive Security](https://www.hacktivesecurity.com/blog/2024/12/10/not-all-roads-lead-to-pwn2own-hardware-hacking-part-1/). However, AI has changed a lot the cat and mouse game of defensive/offensive, and it will take some time (maybe few years) to find a new balance and more calm waters. Maybe, or maybe not.

## References
- https://ssd-disclosure.com/lpe-via-refcount-imbalance-in-the-af_unix-of-ubuntus-kernel/
- https://www.hacktron.ai/blog/watching-gpt-55-sol-ultra-write-a-chrome-exploit-exploit-development-as-we-know-it-is-over
