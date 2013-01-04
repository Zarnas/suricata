/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Christian Rossow <christian.rossow [at] gmail.com>
 *
 * Implements the dummy keyword
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-p2p.h"
#include "util-debug.h"

#include "host.h"

/*prototypes*/
int DetectP2PMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectP2PSetup (DetectEngineCtx *, Signature *, char *);
void DetectP2PFree (void *);
void DetectP2PRegisterTests (void);
uint16_t i=0;
uint32_t ports[100];
uint16_t pg=0;
uint16_t ph=0;
uint16_t pl=0;
uint16_t pperc=50;
uint16_t plimit=1023;

/**
 * \brief Registration function for `dummy` keyword
 */

void DetectP2PRegister(void) {
    sigmatch_table[DETECT_P2P].name = "p2p";
    sigmatch_table[DETECT_P2P].Match = DetectP2PMatch;
    sigmatch_table[DETECT_P2P].Setup = DetectP2PSetup;
    sigmatch_table[DETECT_P2P].Free = DetectP2PFree;
    sigmatch_table[DETECT_P2P].RegisterTests = DetectP2PRegisterTests;
}

/**
 * \brief This function is used to match packets via the dummy rule
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectDummyData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectP2PMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m) {

    int ret = 0;
    DetectP2PSig *dsig = (DetectP2PSig *) m->ctx;
    DetectP2PData *ddata;
    Host *h;

    if (PKT_IS_PSEUDOPKT(p)
        || !PKT_IS_IPV4(p)
        || p->flags & PKT_HOST_SRC_LOOKED_UP
        || p->payload_len == 0) {
        return 0;
    }

    /* TODO: Inspect the packet contents here.
     * Suricata defines a `Packet` structure in decode.h which already defines 
     * many useful elements -- have a look! */

    h = HostGetHostFromHash(&(p->src));
    p->flags |= PKT_HOST_SRC_LOOKED_UP;

    if (h == NULL) {
        printf("host not found!\n");
        return 0;
    }

    ddata = (DetectP2PData *) h->p2p;
    if (!ddata) {
        /* initialize fresh dummydata */
        ddata = SCMalloc(sizeof(DetectP2PData));
        bzero(ddata, sizeof(DetectP2PData));
        h->p2p = ddata;
    }

    
    if (PKT_IS_TCP(p)){
       // if(p->tcph->th_dport != NULL){
          //  ports[i] = p->tcph->th_dport;
         pg++;
         if(p->dp > plimit){
            ph++;
            }
            if(pg>3){
                if(((100*ph)/pg)>pperc){
                printf("\n\nKritischer Wert erreicht\n\n");
                }
                }
        /*        
            ports[i] = p->dp;
            printf("\n\n%d\n\n", ports[i]);
            i++;
            */
//}
}
    (ddata->cnt_packets)++;
    //printf("host found, packets now %d\n", ddata->cnt_packets);
    ret = (ddata->cnt_packets > dsig->max_numpackets);
    
    HostRelease(h);
    return ret;
}

/**
 * \brief this function is used to setup the dummy environment
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param dummystr pointer to the user provided dummy options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectP2PSetup (DetectEngineCtx *de_ctx, Signature *s, char *p2pstr) {

    SigMatch *sm = NULL;
    DetectP2PSig *dsig = NULL;
    
    dsig = SCMalloc(sizeof(DetectP2PSig));
    if (dsig == NULL) { goto error; }

    sm = SigMatchAlloc();
    if (sm == NULL) { goto error; }

    dsig->max_numpackets = atoi(p2pstr);

    sm->type = DETECT_P2P;
    sm->ctx = (void *) dsig;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (dsig != NULL) SCFree(dsig);
    if (sm != NULL) SCFree(sm);
    return -1;
}

void DetectP2PFree (void *ptr) {
    DetectP2PData *ed = (DetectP2PData*) ptr;
    SCFree(ed);
}

void DetectP2PRegisterTests(void) {
    #ifdef UNITTESTS
    // TODO
    #endif
}
