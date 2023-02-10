#ifndef  __BRCM_H
#define __BRCM_H

void     brcm_start(struct ifnet *);                                                                           
void     brcm_init(struct ifnet *);                                                                            
void     brcm_stop(struct ifnet *);                                                                            
void     brcm_iff(struct brcm_softc *);                                                                        
void     brcm_watchdog(struct ifnet *);                                                                        
void     brcm_update_node(void *, struct ieee80211_node *);                                                    
void     brcm_update_nodes(struct brcm_softc *);                                                               
int      brcm_ioctl(struct ifnet *, u_long, caddr_t);                                                          
int      brcm_media_change(struct ifnet *);                                                                    
                                                                                                               
void     brcm_init_board_type(struct brcm_softc *);                                                            
void     brcm_process_blob(struct brcm_softc *, char *, u_char **, size_t *);                                  
                                                                                                               
int      brcm_chip_attach(struct brcm_softc *);                                                                
void     brcm_chip_detach(struct brcm_softc *);                                                                
struct brcm_core *brcm_chip_get_core_idx(struct brcm_softc *, int, int);                                       
struct brcm_core *brcm_chip_get_core(struct brcm_softc *, int);                                                
struct brcm_core *brcm_chip_get_pmu(struct brcm_softc *);                                                      
int      brcm_chip_ai_isup(struct brcm_softc *, struct brcm_core *);                                           
void     brcm_chip_ai_disable(struct brcm_softc *, struct brcm_core *,                                         
             uint32_t, uint32_t);                                                                              
void     brcm_chip_ai_reset(struct brcm_softc *, struct brcm_core *,                                           
             uint32_t, uint32_t, uint32_t);                                                                    
void     brcm_chip_dmp_erom_scan(struct brcm_softc *);                                                         
int      brcm_chip_dmp_get_regaddr(struct brcm_softc *, uint32_t *,                                            
             uint32_t *, uint32_t *);                                                                          
int      brcm_chip_cr4_set_active(struct brcm_softc *, uint32_t);                                              
void     brcm_chip_cr4_set_passive(struct brcm_softc *);                                                       
int      brcm_chip_ca7_set_active(struct brcm_softc *, uint32_t);                                              
void     brcm_chip_ca7_set_passive(struct brcm_softc *);                                                       
int      brcm_chip_cm3_set_active(struct brcm_softc *);                                                        
void     brcm_chip_cm3_set_passive(struct brcm_softc *);                                                       
void     brcm_chip_socram_ramsize(struct brcm_softc *, struct brcm_core *);                                    
void     brcm_chip_sysmem_ramsize(struct brcm_softc *, struct brcm_core *);                                    
void     brcm_chip_tcm_ramsize(struct brcm_softc *, struct brcm_core *);                                       
void     brcm_chip_tcm_rambase(struct brcm_softc *);

int      brcm_proto_bcdc_query_dcmd(struct brcm_softc *, int,                                                  
             int, char *, size_t *);                                                                           
int      brcm_proto_bcdc_set_dcmd(struct brcm_softc *, int,                                                    
             int, char *, size_t);                                                                             
void     brcm_proto_bcdc_rx(struct brcm_softc *, struct mbuf *,                                                
             struct mbuf_list *);                                                                              
int      brcm_proto_bcdc_txctl(struct brcm_softc *, int, char *, size_t *);                                    
void     brcm_proto_bcdc_rxctl(struct brcm_softc *, char *, size_t);                                           
                                                                                                               
int      brcm_fwvar_cmd_get_data(struct brcm_softc *, int, void *, size_t);                                    
int      brcm_fwvar_cmd_set_data(struct brcm_softc *, int, void *, size_t);                                    
int      brcm_fwvar_cmd_get_int(struct brcm_softc *, int, uint32_t *);                                         
int      brcm_fwvar_cmd_set_int(struct brcm_softc *, int, uint32_t);                                           
int      brcm_fwvar_var_get_data(struct brcm_softc *, char *, void *, size_t);                                 
int      brcm_fwvar_var_set_data(struct brcm_softc *, char *, void *, size_t);                                 
int      brcm_fwvar_var_get_int(struct brcm_softc *, char *, uint32_t *);                                      
int      brcm_fwvar_var_set_int(struct brcm_softc *, char *, uint32_t);                                        
                                                                                                               
uint32_t brcm_chan2spec(struct brcm_softc *, struct ieee80211_channel *);          

uint32_t brcm_chan2spec_d11n(struct brcm_softc *, struct ieee80211_channel *);                                 
uint32_t brcm_chan2spec_d11ac(struct brcm_softc *, struct ieee80211_channel *);                                
uint32_t brcm_spec2chan(struct brcm_softc *, uint32_t);                                                        
uint32_t brcm_spec2chan_d11n(struct brcm_softc *, uint32_t);                                                   
uint32_t brcm_spec2chan_d11ac(struct brcm_softc *, uint32_t);                                                  
                                                                                                               
void     brcm_connect(struct brcm_softc *);                                                                    
#ifndef IEEE80211_STA_ONLY                                                                                     
void     brcm_hostap(struct brcm_softc *);                                                                     
#endif                                                                                                         
void     brcm_scan(struct brcm_softc *);                                                                       
void     brcm_scan_abort(struct brcm_softc *);                                                                 
                                                                                                               
void     brcm_task(void *);                                                                                    
void     brcm_do_async(struct brcm_softc *,                                                                    
             void (*)(struct brcm_softc *, void *), void *, int);

int brcm_set_key(struct ieee80211com *, struct ieee80211_node *,
                 struct ieee80211_key *);

oid     brcm_delete_key(struct ieee80211com *, struct ieee80211_node *,                                       
             struct ieee80211_key *);                                                                          
int      brcm_send_mgmt(struct ieee80211com *, struct ieee80211_node *,                                        
             int, int, int);                                                                                   
int      brcm_newstate(struct ieee80211com *, enum ieee80211_state, int);                                      
                                                                                                               
void     brcm_set_key_cb(struct brcm_softc *, void *);                                                         
void     brcm_delete_key_cb(struct brcm_softc *, void *);                                                      
void     brcm_rx_event_cb(struct brcm_softc *, struct mbuf *);                                                 
                                                                                                               
struct mbuf *brcm_newbuf(void);                                                                                
#ifndef IEEE80211_STA_ONLY                                                                                     
void     brcm_rx_auth_ind(struct brcm_softc *, struct brcm_event *, size_t);                                   
void     brcm_rx_assoc_ind(struct brcm_softc *, struct brcm_event *, size_t, int);                             
void     brcm_rx_deauth_ind(struct brcm_softc *, struct brcm_event *, size_t);                                 
void     brcm_rx_disassoc_ind(struct brcm_softc *, struct brcm_event *, size_t);                               
void     brcm_rx_leave_ind(struct brcm_softc *, struct brcm_event *, size_t, int);                             
#endif                                                                                                         
void     brcm_rx_event(struct brcm_softc *, struct mbuf *);

void     brcm_scan_node(struct brcm_softc *, struct brcm_bss_info *, size_t);                                  
                     Declaration of 'struct ieee80211_nodereq' will not be visible outside of this function    
extern void ieee80211_node2req(struct ieee80211com *,                                                          
             const struct ieee80211_node *, struct ieee80211_nodereq *);                                       
extern void ieee80211_req2node(struct ieee80211com *,                                                          
             const struct ieee80211_nodereq *, struct ieee80211_node *); 


#endif
