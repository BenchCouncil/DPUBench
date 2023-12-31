#include <errno.h>
#include <string.h>

#include <doca_log.h>
#include <doca_compress.h>

#include <utils.h>

DOCA_LOG_REGISTER(compress_SCAN);

#define NB_CHUNKS 6

struct compress_scan_ctx {
	char *data_buffer;			/* Data buffer */
	int qp_id;				/* QP index */
	uint16_t nb_qp;				/* Number of QPs to use */
	char *pci_address;			/* compress PCI address to use */
	char *compiled_rules;			/* Compiled compress rules */
	struct doca_compress_buffer buffer;	/* Job request buffer */
	struct doca_compress *doca_compress;		/* DOCA compress interface */
	struct doca_compress_device *compress_dev;	/* DOCA compress device interface */
	struct doca_compress_mempool *matches_mp;	/* DOCA compress matches mempool */
};

/*
 * Printing the compress results
 */
static void
compress_scan_report_results(struct compress_scan_ctx *compress_cfg, struct doca_compress_job_response *job_responses,
	int nb_responses, int chunk_len)
{
	int idx;
	int offset;
	struct doca_compress_match *ptr;

	for (idx = 0; idx < nb_responses; idx++) {
		if (job_responses[idx].num_matches == 0)
			continue;
		ptr = job_responses[idx].matches;
		/* Match start is relative to the whole file data and not the current chunk */
		offset = job_responses[idx].id * chunk_len;
		while (ptr != NULL) {
			DOCA_LOG_INFO("date rule id: %d", ptr->rule_id);
			compress_cfg->data_buffer[ptr->match_start + offset + ptr->length] = '\0';
			DOCA_LOG_INFO("date value: %*s", ptr->length,
			       (char *)(compress_cfg->data_buffer + offset + ptr->match_start));
			struct doca_compress_match *const to_release_match = ptr;

			ptr = ptr->next;
			doca_compress_mempool_obj_put(compress_cfg->matches_mp, to_release_match);
		}
	}
}

/*
 * Initialize DOCA compress resources
 * compress_cfg: compress configuration struct
 * Init DOCA compress according to compress_cfg configuration struct fields
 */
static int
compress_scan_init(struct compress_scan_ctx *compress_cfg)
{
	int ret, qp_id;
	const int mempool_size = 8;
	/* Create a doca reg instance */
	compress_cfg->doca_compress = doca_compress_create();
	if (compress_cfg->doca_compress == NULL) {
		DOCA_LOG_ERR("Unable to create compress device.");
		return -ENOMEM;
	}
	compress_cfg->compress_dev = doca_compress_create_pre_configured_compress_impl("bf2");

	/* Init compress device */
	ret = compress_cfg->compress_dev->init_fn(compress_cfg->compress_dev, compress_cfg->pci_address);
	if (ret < 0) {
		DOCA_LOG_ERR("Unable to initialize compress device. [%s]", strerror(abs(ret)));
		return ret;
	}

	/* Set the compress device as the main HW accelerator */
	ret = doca_compress_hw_device_set(compress_cfg->doca_compress, compress_cfg->compress_dev);
	if (ret < 0) {
		DOCA_LOG_ERR("Unable to set compress device. [%s]", strerror(abs(ret)));
		return ret;
	}

	/* Init matches memory pool */
	compress_cfg->matches_mp = doca_compress_mempool_create(sizeof(struct doca_compress_match), mempool_size);
	if (compress_cfg->matches_mp == NULL) {
		DOCA_LOG_ERR("Unable to create matches mempool.");
		return -ENOMEM;
	}

	/* Configure QP to memory pool, our sample uses 1 qp */
	ret = doca_compress_num_qps_set(compress_cfg->doca_compress, compress_cfg->nb_qp);
	if (ret < 0) {
		DOCA_LOG_ERR("Unable to configure %d QPs. [%s]", compress_cfg->nb_qp, strerror(abs(ret)));
		return ret;
	}

	/* Set qp to compress mempool, attach qp index=0, uses only one qp */
	qp_id = compress_cfg->nb_qp - 1;
	ret = doca_compress_qp_mempool_set(compress_cfg->doca_compress, compress_cfg->matches_mp, qp_id);
	if (ret < 0) {
		DOCA_LOG_ERR("Unable to register pool with QP-%d. [%s]", qp_id, strerror(abs(ret)));
		return ret;
	}

	/* Load compiled rules into the compress */
	ret = doca_compress_program_compiled_rules_file(compress_cfg->doca_compress, compress_cfg->compiled_rules, NULL);
	if (ret < 0) {
		DOCA_LOG_ERR("Unable to program rules file. [%s]", strerror(abs(ret)));
		return ret;
	}

	/* Start doca compress */
	ret = doca_compress_start(compress_cfg->doca_compress);
	if (ret < 0) {
		DOCA_LOG_ERR("Unable to start doca compress. [%s]", strerror(abs(ret)));
		return ret;
	}
	return 0;
}

/*
 * Enqueue job to DOCA compress qp
 * compress_cfg: compress_scan_ctx configuration struct
 * job_request: compress job request, already initialized with first chunk.
 * remaining_bytes: the remaining bytes to send all jobs (chunks).
 */
uint32_t compress_scan_enq_job(struct compress_scan_ctx *compress_cfg, struct doca_compress_job_request *job_request,
	uint32_t *remaining_bytes)
{
	int ret;
	uint32_t nb_enqueued = 0;

	while (*remaining_bytes > 0) {
		ret = doca_compress_enqueue(compress_cfg->doca_compress, compress_cfg->qp_id, job_request, false);
		if (ret < 0)
			APP_EXIT("Failed to enqueue jobs");
		nb_enqueued++;
		*remaining_bytes -= compress_cfg->buffer.length;
		/* Update the next job buffer details (next chunk) */
		job_request->id++;
		compress_cfg->buffer.address += compress_cfg->buffer.length;
		/* In case the last chunk length less than the supposed chunk size */
		if (compress_cfg->buffer.length > *remaining_bytes)
			compress_cfg->buffer.length = *remaining_bytes;
	}
	return nb_enqueued;
}

uint32_t compress_scan_deq_job(struct compress_scan_ctx *compress_cfg, int chunk_len)
{
	int ret;
	uint32_t nb_dequeued = 0;
	const int responses_size = NB_CHUNKS;
	struct doca_compress_job_response job_responses[responses_size];

	do {
		ret = doca_compress_dequeue(compress_cfg->doca_compress, compress_cfg->qp_id, job_responses, responses_size);
		if (ret < 0)
			APP_EXIT("Failed to dequeue results. [%s]", strerror(abs(ret)));

		compress_scan_report_results(compress_cfg, job_responses, ret, chunk_len);
		nb_dequeued += (uint32_t)ret;
	} while (ret != 0);

	return nb_dequeued;
}

/*
 * compress scan cleanup, destroy all DOCA compress resources
 */
static void
compress_scan_destroy(struct compress_scan_ctx *compress_cfg)
{
	doca_compress_buffer_release_mkey(compress_cfg->compress_dev);
	doca_compress_stop(compress_cfg->doca_compress);
	doca_compress_destroy(compress_cfg->doca_compress);
	doca_compress_mempool_destroy(compress_cfg->matches_mp);
	compress_cfg->doca_compress = NULL;
	if (compress_cfg->compress_dev != NULL) {
		compress_cfg->compress_dev->cleanup_fn(compress_cfg->compress_dev);
		compress_cfg->compress_dev->destroy_fn(compress_cfg->compress_dev);
		compress_cfg->compress_dev = NULL;
	}
}

/*
 * Run DOCA compress sample
 * data_buffer: User data used to find the matches
 * data_buffer_len: data_buffer length
 * pci_addr: pci address for HW compress device
 * rules_path: compress rules file path(compiled rules(rof2.binary))
 */
int
compress_scan(char *data_buffer, size_t data_buffer_len, char *pci_addr, char *rules_path)
{
	if (data_buffer == NULL || pci_addr == NULL || rules_path == NULL || data_buffer_len == 0)
		return -EINVAL;

	int ret;
	uint32_t remaining_bytes, nb_dequeued = 0, nb_enqueued = 0;
	const int nb_chunks = NB_CHUNKS;
	const int chunk_len = (data_buffer_len < nb_chunks) ? data_buffer_len : 1 + (data_buffer_len/nb_chunks);
	struct compress_scan_ctx rgx_cfg = {0};
	struct doca_compress_job_request job_request = {0};

	/* Set DOCA compress configuration fields in compress_cfg according to our sample */
	rgx_cfg.nb_qp = 1;
	rgx_cfg.qp_id = 0;
	rgx_cfg.data_buffer = data_buffer;
	rgx_cfg.pci_address = pci_addr;
	rgx_cfg.compiled_rules = rules_path;

	/* Init DOCA compress */
	ret = compress_scan_init(&rgx_cfg);
	if (ret < 0)
		return ret;

	/* Generate mkey for user data */
	if (doca_compress_buffer_generate_mkey(rgx_cfg.compress_dev, data_buffer, data_buffer_len, &rgx_cfg.buffer.mkey) != 0)
		APP_EXIT("Unable to generate data mkey.");

	rgx_cfg.buffer.address = data_buffer;	/* Pointer to user data */
	rgx_cfg.buffer.length = chunk_len;	/* Set first chunk size = chunk_len */
	rgx_cfg.buffer.has_mkey = 1;		/* Generate mkey for user data */
	job_request.buffer = &rgx_cfg.buffer;	/* Attach compress buffer to the job request */
	job_request.rule_group_ids[0] = 1;

	remaining_bytes = data_buffer_len;

	/* The main loop, enqueues jobs (chunks) and dequeues for results. */
	do {
		nb_enqueued += compress_scan_enq_job(&rgx_cfg, &job_request, &remaining_bytes);
		nb_dequeued += compress_scan_deq_job(&rgx_cfg, chunk_len);
	} while (remaining_bytes > 0 || nb_dequeued != nb_enqueued);

	/* compress scan recognition cleanup */
	compress_scan_destroy(&rgx_cfg);
	return 0;
}
