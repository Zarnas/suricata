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
 * \authors Michael Neuschulte, Markus Alberts
 *
 * Implements the p2p keyword
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
uint16_t pg=0; //Sum of ports
uint16_t ph=0; //Sum of highports
uint32_t perc_limit=0; //Percent limit
uint32_t port_limit=0; //Highport definition
uint32_t sum_hport_limit=0; //Highport limit

/**
 * \brief Registration function for `p2p` keyword
 */

void DetectP2PRegister(void) {
    sigmatch_table[DETECT_P2P].name = "p2p";
    sigmatch_table[DETECT_P2P].Match = DetectP2PMatch;
    sigmatch_table[DETECT_P2P].Setup = DetectP2PSetup;
    sigmatch_table[DETECT_P2P].Free = DetectP2PFree;
    sigmatch_table[DETECT_P2P].RegisterTests = DetectP2PRegisterTests;
}

/**
 * \brief This function is used to match packets via the p2p rule
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectP2PData
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

    /* Inspect the packet contents here.
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
        /* initialize fresh p2pdata */
        ddata = SCMalloc(sizeof(DetectP2PData));
        bzero(ddata, sizeof(DetectP2PData));
        h->p2p = ddata;
    }
/*    Relics:
  //  printf("\n\n%i\n\n", sum_hport_limit);
    if (PKT_IS_TCP(p)){
       // if(p->tcph->th_dport != NULL){
          //  ports[i] = p->tcph->th_dport;
         pg++;
         if(p->dp > port_limit){
            ph++;
            }
            if(pg>3){
                if((((100*ph)/pg)>perc_limit) || (ph>sum_hport_limit)){
        //        printf("\n\nKritischer Wert erreicht\n\n");
                ret=1;
                }
                }
                
            ports[i] = p->dp;
            printf("\n\n%d\n\n", ports[i]);
            i++;
            
//} */
    //Calculates the % share of high-port connections.
    //If the percentage share, or the total numer of high-port
    //connections are too high, an alarm will be thrown
    (ddata->cnt_packets)++;
 // printf("\n\nhost found, packets now %d\n\n", ddata->cnt_packets);
    ret = (ddata->cnt_packets > dsig->max_numpackets);
    if(ddata->cnt_packets == 1){
    pg=0;
    ph=0;
    }
    if(PKT_IS_TCP(p)){
    pg++;
        if(p->dp>port_limit){
        ph++;
        }
        if(pg>3){
            if((((100*ph)/pg)>perc_limit)||(ph>sum_hport_limit)){
    //            printf("High ports fly high: %d", ph);
                ret=1;
                }
                }

    HostRelease(h);
    return ret;
}
}
/**
 * \brief this function is used to setup the p2p environment
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param p2pstr pointer to the user provided p2p options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectP2PSetup (DetectEngineCtx *de_ctx, Signature *s, char *p2pstr) {

    SigMatch *sm = NULL;
    DetectP2PSig *dsig = NULL;
    char* tok;
    char* save;
    uint32_t tmp;
    
    dsig = SCMalloc(sizeof(DetectP2PSig));
    if (dsig == NULL) { goto error; }

    sm = SigMatchAlloc();
    if (sm == NULL) { goto error; }

   // dsig->max_numpackets = atoi(p2pstr);

    tok = strtok(p2pstr,": ,");
    while (tok != NULL){
        save = tok;
        tok = strtok(NULL, ": ,");
        if((tmp = atoi(tok)) == 0){
        return -1;
        }

        if(strcmp(save, "perc_limit") == 0){
            if(tmp>=0 && tmp<=100){
            perc_limit=tmp;}}
            else if(strcmp(save, "port_limit") == 0){
                if(tmp>=1 && tmp<=65535){
                port_limit=tmp;}}
            else if (strcmp(save, "sum_hport_limit") == 0){
                sum_hport_limit=tmp;}
            tok=strtok(NULL, ": ,");
}
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
