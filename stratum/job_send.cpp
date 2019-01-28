
#include "stratum.h"

static int g_job_next_id = 0;

int job_get_jobid()
{
	CommonLock(&g_job_create_mutex);
	int jobid = ++g_job_next_id;

	CommonUnlock(&g_job_create_mutex);
	return jobid;
}

void build_merkleroot(YAAMP_JOB_VALUES *submitvalues, YAAMP_JOB_TEMPLATE *templ)
{
    //debuglog("Coinbase2 (txhash) %s\n", templ->coinb2);
	/*
    sprintf(submitvalues->coinbase, "%s%s%s%s", templ->coinb1, nonce1, nonce2, templ->coinb2);
	int coinbase_len = strlen(submitvalues->coinbase);

	unsigned char coinbase_bin[1024];
	memset(coinbase_bin, 0, 1024);
	binlify(coinbase_bin, submitvalues->coinbase);

	char doublehash[128];
	memset(doublehash, 0, 128);

	// some (old) wallet/algos need a simple SHA256 (blakecoin, whirlcoin, groestlcoin...)
	YAAMP_HASH_FUNCTION merkle_hash = sha256_double_hash_hex;
	if (g_current_algo->merkle_func)
		merkle_hash = g_current_algo->merkle_func;
	merkle_hash((char *)coinbase_bin, doublehash, coinbase_len/2);

	string merkleroot = merkle_with_first(templ->txsteps, doublehash);
	ser_string_be(merkleroot.c_str(), submitvalues->merkleroot_be, 8);

#ifdef MERKLE_DEBUGLOG
	printf("merkle root %s\n", merkleroot.c_str());
#endif*/
}

static void job_mining_notify_buffer(YAAMP_JOB *job, char *buffer, YAAMP_CLIENT *client)
{
	YAAMP_JOB_TEMPLATE *templ = job->templ;

	if (!strcmp(g_stratum_algo, "lbry")) {
		sprintf(buffer, "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
			"\"%x\",\"%s\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
			job->id, templ->prevhash_be, templ->claim_be, templ->coinb1, templ->coinb2,
			templ->txmerkles, templ->version, templ->nbits, templ->ntime);
		return;
	} else if (strlen(templ->extradata_hex) == 128) {
		// LUX smart contract state hashes (like lbry extra field, here the 2 root hashes in one)
		sprintf(buffer, "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
			"\"%x\",\"%s\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
			job->id, templ->prevhash_be, templ->extradata_be, templ->coinb1, templ->coinb2,
			templ->txmerkles, templ->version, templ->nbits, templ->ntime);
		return;
	} else if (!strcmp(g_stratum_algo, "equihash")) {
        char ntime_be[8+1] = {0};
        char nbits_be[8+1] = {0};
        char version_be[8+1] = {0};
        string_be_len(templ->ntime, ntime_be, 4);
        string_be_len(templ->nbits, nbits_be, 4);
        string_be_len(templ->version, version_be, 4);
        sprintf(buffer, "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
            "\"%x\",\"%s\",\"%s\",\"%.64s\",\"%s\",\"%s\",\"%s\",true]}\n",
            job->id, version_be, templ->prevhash_be, templ->merkleroot, 
            "0000000000000000000000000000000000000000000000000000000000000000",
            ntime_be, nbits_be);
		return;                
    }

	// standard stratum
	sprintf(buffer, "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"%x\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
		job->id, templ->prevhash_be, templ->coinb1, templ->coinb2, templ->txmerkles, templ->version, templ->nbits, templ->ntime);
}

static YAAMP_JOB *job_get_last(int coinid)
{
	g_list_job.Enter();
	for(CLI li = g_list_job.first; li; li = li->prev)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;
		if(!job->coind) continue;
		if(coinid > 0 && job->coind->id != coinid) continue;

		g_list_job.Leave();
		return job;
	}

	g_list_job.Leave();
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////

void job_send_last(YAAMP_CLIENT *client)
{
#ifdef NO_EXCHANGE
	// prefer user coin first (if available)
	YAAMP_JOB *job = job_get_last(client->coinid);
	if(!job) job = job_get_last(0);
#else
	YAAMP_JOB *job = job_get_last(0);
#endif
	if(!job) return;
    
    debuglog("STOP TEST job_send_last [0]\n");

	YAAMP_JOB_TEMPLATE *templ = job->templ;
	client->jobid_sent = job->id;
    
    debuglog("STOP TEST job_send_last [1]\n");

	char buffer[YAAMP_SMALLBUFSIZE];
	job_mining_notify_buffer(job, buffer, client);
    
    debuglog("STOP TEST job_send_last [2]\n");

    debuglog("Sending raw job buffer (job_send_last): %s\n", &buffer);
	socket_send_raw(client->sock, buffer, strlen(buffer));
}

void job_send_jobid(YAAMP_CLIENT *client, int jobid)
{
	YAAMP_JOB *job = (YAAMP_JOB *)object_find(&g_list_job, jobid, true);
	if(!job)
	{
		job_send_last(client);
		return;
	}

	char buffer[YAAMP_SMALLBUFSIZE];
	job_mining_notify_buffer(job, buffer, client);

	YAAMP_JOB_TEMPLATE *templ = job->templ;
	client->jobid_sent = job->id;

    debuglog("Sending raw job buffer (job_send_jobid): %s\n", &buffer);
	socket_send_raw(client->sock, buffer, strlen(buffer));
	object_unlock(job);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////

void job_broadcast(YAAMP_JOB *job)
{
	int s1 = current_timestamp_dms();
	int count = 0;
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 100000; // max time to push to a socket (very fast)

	YAAMP_JOB_TEMPLATE *templ = job->templ;

	char buffer[YAAMP_SMALLBUFSIZE];

	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted) continue;
		if(!client->sock) continue;
	//	if(client->reconnecting && client->locked) continue;

		if(client->jobid_next != job->id) continue;
		if(client->jobid_sent == job->id) continue;

		client->jobid_sent = job->id;
		client_add_job_history(client, job->id);

        strcpy(client->algo, job->algo);
		client_adjust_difficulty(client);

		setsockopt(client->sock->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        job_mining_notify_buffer(job, buffer, client);
        //std::string json_str = "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"19f73294293248080c9c\",\"04000000\",\"d834e1d5708d7f100651364a96d4bdec633af12fd00b01e8355ffa0600000000\",\"2642f5c32ace0d15b6eae03cd18257b66a1fc5a24b22015a7e60a132b9d5262d\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"3b9e825b\",\"7799081c\",true]}";
        //const char *buffer2 = json_str.c_str();                
        debuglog("Sending raw job buffer (job_broadcast): %s\n", &buffer);
		if (socket_send_raw(client->sock, buffer, strlen(buffer)) == -1) {
			int err = errno;
			client->broadcast_timeouts++;
			// too much timeouts, disconnect him
			if (client->broadcast_timeouts >= 3) {
				shutdown(client->sock->sock, SHUT_RDWR);
				clientlog(client, "unable to send job, sock err %d (%d times)", err, client->broadcast_timeouts);
				if(client->workerid && !client->reconnecting) {
				//	CommonLock(&g_db_mutex);
					db_clear_worker(g_db, client);
				//	CommonUnlock(&g_db_mutex);
				}
				object_delete(client);
			}
		}
		count++;
	}

	g_list_client.Leave();
	g_last_broadcasted = time(NULL);

	int s2 = current_timestamp_dms();
	if(!count) return;

	///////////////////////

	uint64_t coin_target = decode_compact(templ->nbits);
	if (templ->nbits && !coin_target) coin_target = 0xFFFF000000000000ULL; // under decode_compact min diff
	double coin_diff = target_to_diff(coin_target);

	debuglog("%s %d - diff %.9f job %x to %d/%d/%d clients, hash %.3f/%.3f in %.1f ms\n", job->name,
		templ->height, coin_diff, job->id, count, job->count, g_list_client.count, job->speed, job->maxspeed, 0.1*(s2-s1));

//	for(int i=0; i<templ->auxs_size; i++)
//	{
//		if(!templ->auxs[i]) continue;
//		YAAMP_COIND *coind_aux = templ->auxs[i]->coind;
//
//		unsigned char target_aux[1024];
//		binlify(target_aux, coind_aux->aux.target);
//
//		uint64_t coin_target = get_hash_difficulty(target_aux);
//		double coin_diff = target_to_diff(coin_target);
//
//		debuglog("%s %d - diff %.9f chainid %d [%d]\n", coind_aux->symbol, coind_aux->height, coin_diff,
//				coind_aux->aux.chainid, coind_aux->aux.index);
//	}

}







//	double maxhash = 0;
//	if(job->remote)
//	{
//		sprintf(name, "JOB%d%s (%.3f)", job->remote->id, job->remote->nonce2size == 2? "*": "", job->remote->speed_avg);
//		maxhash = job->remote->speed;
//	}
//	else
//	{
//		strcpy(name, job->coind->symbol);
//		for(int i=0; i<templ->auxs_size; i++)
//		{
//			if(!templ->auxs[i]) continue;
//			YAAMP_COIND *coind_aux = templ->auxs[i]->coind;
//
//			sprintf(name_auxs+strlen(name_auxs), ", %s %d", coind_aux->symbol, templ->auxs[i]->height);
//		}
//
//		maxhash = coind_nethash(job->coind)*coind_profitability(job->coind)/(g_current_algo->profit? g_current_algo->profit: 1);
//	}

