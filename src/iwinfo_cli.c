/*
 * iwinfo - Wireless Information Library - Command line frontend
 *
 *   Copyright (C) 2011 Jo-Philipp Wich <xm@subsignal.org>
 *
 * The iwinfo library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * The iwinfo library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with the iwinfo library. If not, see http://www.gnu.org/licenses/.
 */


#include <stdio.h>
#include <glob.h>


#include "iwinfo.h"


static char * format_bssid(unsigned char *mac)
{
    static char buf[18];

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return buf;
}

static char * format_ssid(char *ssid)
{
    static char buf[IWINFO_ESSID_MAX_SIZE+3];

    if (ssid && ssid[0])
        snprintf(buf, sizeof(buf), "\"%s\"", ssid);
    else
        snprintf(buf, sizeof(buf), "unknown");

    return buf;
}

//static char * format_channel(int ch)
//{
//	static char buf[8];

//	if (ch <= 0)
//		snprintf(buf, sizeof(buf), "unknown");
//	else
//		snprintf(buf, sizeof(buf), "%d", ch);

//	return buf;
//}

//static char * format_frequency(int freq)
//{
//	static char buf[10];

//	if (freq <= 0)
//		snprintf(buf, sizeof(buf), "unknown");
//	else
//		snprintf(buf, sizeof(buf), "%.3f GHz", ((float)freq / 1000.0));

//	return buf;
//}

//static char * format_txpower(int pwr)
//{
//	static char buf[10];

//	if (pwr < 0)
//		snprintf(buf, sizeof(buf), "unknown");
//	else
//		snprintf(buf, sizeof(buf), "%d dBm", pwr);

//	return buf;
//}

//static char * format_quality(int qual)
//{
//	static char buf[8];

//	if (qual < 0)
//		snprintf(buf, sizeof(buf), "unknown");
//	else
//		snprintf(buf, sizeof(buf), "%d", qual);

//	return buf;
//}

//static char * format_quality_max(int qmax)
//{
//	static char buf[8];

//	if (qmax < 0)
//		snprintf(buf, sizeof(buf), "unknown");
//	else
//		snprintf(buf, sizeof(buf), "%d", qmax);

//	return buf;
//}

static char * format_signal(int sig)
{
    static char buf[10];

    if (!sig)
        snprintf(buf, sizeof(buf), "unknown");
    else
        snprintf(buf, sizeof(buf), "%d dBm", sig);

    return buf;
}

static char * format_noise(int noise)
{
    static char buf[10];

    if (!noise)
        snprintf(buf, sizeof(buf), "unknown");
    else
        snprintf(buf, sizeof(buf), "%d dBm", noise);

    return buf;
}

//static char * format_rate(int rate)
//{
//	static char buf[14];

//	if (rate <= 0)
//		snprintf(buf, sizeof(buf), "unknown");
//	else
//		snprintf(buf, sizeof(buf), "%d.%d MBit/s",
//			rate / 1000, (rate % 1000) / 100);

//	return buf;
//}

//static char * format_enc_ciphers(int ciphers)
//{
//	static char str[128] = { 0 };
//	char *pos = str;

//	if (ciphers & IWINFO_CIPHER_WEP40)
//		pos += sprintf(pos, "WEP-40, ");

//	if (ciphers & IWINFO_CIPHER_WEP104)
//		pos += sprintf(pos, "WEP-104, ");

//	if (ciphers & IWINFO_CIPHER_TKIP)
//		pos += sprintf(pos, "TKIP, ");

//	if (ciphers & IWINFO_CIPHER_CCMP)
//		pos += sprintf(pos, "CCMP, ");

//	if (ciphers & IWINFO_CIPHER_WRAP)
//		pos += sprintf(pos, "WRAP, ");

//	if (ciphers & IWINFO_CIPHER_AESOCB)
//		pos += sprintf(pos, "AES-OCB, ");

//	if (ciphers & IWINFO_CIPHER_CKIP)
//		pos += sprintf(pos, "CKIP, ");

//	if (!ciphers || (ciphers & IWINFO_CIPHER_NONE))
//		pos += sprintf(pos, "NONE, ");

//	*(pos - 2) = 0;

//	return str;
//}

//static char * format_enc_suites(int suites)
//{
//	static char str[64] = { 0 };
//	char *pos = str;

//	if (suites & IWINFO_KMGMT_PSK)
//		pos += sprintf(pos, "PSK/");

//	if (suites & IWINFO_KMGMT_8021x)
//		pos += sprintf(pos, "802.1X/");

//	if (!suites || (suites & IWINFO_KMGMT_NONE))
//		pos += sprintf(pos, "NONE/");

//	*(pos - 1) = 0;

//	return str;
//}

//static char * format_encryption(struct iwinfo_crypto_entry *c)
//{
//	static char buf[512];

//	if (!c)
//	{
//		snprintf(buf, sizeof(buf), "unknown");
//	}
//	else if (c->enabled)
//	{
//		/* WEP */
//		if (c->auth_algs && !c->wpa_version)
//		{
//			if ((c->auth_algs & IWINFO_AUTH_OPEN) &&
//				(c->auth_algs & IWINFO_AUTH_SHARED))
//			{
//				snprintf(buf, sizeof(buf), "WEP Open/Shared (%s)",
//					format_enc_ciphers(c->pair_ciphers));
//			}
//			else if (c->auth_algs & IWINFO_AUTH_OPEN)
//			{
//				snprintf(buf, sizeof(buf), "WEP Open System (%s)",
//					format_enc_ciphers(c->pair_ciphers));
//			}
//			else if (c->auth_algs & IWINFO_AUTH_SHARED)
//			{
//				snprintf(buf, sizeof(buf), "WEP Shared Auth (%s)",
//					format_enc_ciphers(c->pair_ciphers));
//			}
//		}

//		/* WPA */
//		else if (c->wpa_version)
//		{
//			switch (c->wpa_version) {
//				case 3:
//					snprintf(buf, sizeof(buf), "mixed WPA/WPA2 %s (%s)",
//						format_enc_suites(c->auth_suites),
//						format_enc_ciphers(c->pair_ciphers | c->group_ciphers));
//					break;

//				case 2:
//					snprintf(buf, sizeof(buf), "WPA2 %s (%s)",
//						format_enc_suites(c->auth_suites),
//						format_enc_ciphers(c->pair_ciphers | c->group_ciphers));
//					break;

//				case 1:
//					snprintf(buf, sizeof(buf), "WPA %s (%s)",
//						format_enc_suites(c->auth_suites),
//						format_enc_ciphers(c->pair_ciphers | c->group_ciphers));
//					break;
//			}
//		}
//		else
//		{
//			snprintf(buf, sizeof(buf), "none");
//		}
//	}
//	else
//	{
//		snprintf(buf, sizeof(buf), "none");
//	}

//	return buf;
//}

//static char * format_hwmodes(int modes)
//{
//	static char buf[12];

//	if (modes <= 0)
//		snprintf(buf, sizeof(buf), "unknown");
//	else
//		snprintf(buf, sizeof(buf), "802.11%s%s%s%s",
//			(modes & IWINFO_80211_A) ? "a" : "",
//			(modes & IWINFO_80211_B) ? "b" : "",
//			(modes & IWINFO_80211_G) ? "g" : "",
//			(modes & IWINFO_80211_N) ? "n" : "");

//	return buf;
//}

//static char * format_assocrate(struct iwinfo_rate_entry *r)
//{
//	static char buf[40];
//	char *p = buf;
//	int l = sizeof(buf);

//	if (r->rate <= 0)
//	{
//		snprintf(buf, sizeof(buf), "unknown");
//	}
//	else
//	{
//		p += snprintf(p, l, "%s", format_rate(r->rate));
//		l = sizeof(buf) - (p - buf);

//		if (r->mcs >= 0)
//		{
//			p += snprintf(p, l, ", MCS %d, %dMHz", r->mcs, 20 + r->is_40mhz*20);
//			l = sizeof(buf) - (p - buf);

//			if (r->is_short_gi)
//				p += snprintf(p, l, ", short GI");
//		}
//	}

//	return buf;
//}


//static const char * print_type(const struct iwinfo_ops *iw, const char *ifname)
//{
//	const char *type = iwinfo_type(ifname);
//	return type ? type : "unknown";
//}

//static char * print_hardware_id(const struct iwinfo_ops *iw, const char *ifname)
//{
//	static char buf[20];
//	struct iwinfo_hardware_id ids;

//	if (!iw->hardware_id(ifname, (char *)&ids))
//	{
//		snprintf(buf, sizeof(buf), "%04X:%04X %04X:%04X",
//			ids.vendor_id, ids.device_id,
//			ids.subsystem_vendor_id, ids.subsystem_device_id);
//	}
//	else
//	{
//		snprintf(buf, sizeof(buf), "unknown");
//	}

//	return buf;
//}

//static char * print_hardware_name(const struct iwinfo_ops *iw, const char *ifname)
//{
//	static char buf[128];

//	if (iw->hardware_name(ifname, buf))
//		snprintf(buf, sizeof(buf), "unknown");

//	return buf;
//}

//static char * print_txpower_offset(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int off;
//	static char buf[12];

//	if (iw->txpower_offset(ifname, &off))
//		snprintf(buf, sizeof(buf), "unknown");
//	else if (off != 0)
//		snprintf(buf, sizeof(buf), "%d dB", off);
//	else
//		snprintf(buf, sizeof(buf), "none");

//	return buf;
//}

//static char * print_frequency_offset(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int off;
//	static char buf[12];

//	if (iw->frequency_offset(ifname, &off))
//		snprintf(buf, sizeof(buf), "unknown");
//	else if (off != 0)
//		snprintf(buf, sizeof(buf), "%.3f GHz", ((float)off / 1000.0));
//	else
//		snprintf(buf, sizeof(buf), "none");

//	return buf;
//}

//static char * print_ssid(const struct iwinfo_ops *iw, const char *ifname)
//{
//	char buf[IWINFO_ESSID_MAX_SIZE+1] = { 0 };

//	if (iw->ssid(ifname, buf))
//		memset(buf, 0, sizeof(buf));

//	return format_ssid(buf);
//}

static char * print_bssid(const struct iwinfo_ops *iw, const char *ifname)
{
    static char buf[18] = { 0 };

    if (iw->bssid(ifname, buf))
        snprintf(buf, sizeof(buf), "00:00:00:00:00:00");

    return buf;
}

//static char * print_mode(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int mode;
//	static char buf[128];

//	if (iw->mode(ifname, &mode))
//		mode = IWINFO_OPMODE_UNKNOWN;

//	snprintf(buf, sizeof(buf), "%s", IWINFO_OPMODE_NAMES[mode]);

//	return buf;
//}

//static char * print_channel(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int ch;
//	if (iw->channel(ifname, &ch))
//		ch = -1;

//	return format_channel(ch);
//}

//static char * print_frequency(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int freq;
//	if (iw->frequency(ifname, &freq))
//		freq = -1;

//	return format_frequency(freq);
//}

//static char * print_txpower(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int pwr, off;
//	if (iw->txpower_offset(ifname, &off))
//		off = 0;

//	if (iw->txpower(ifname, &pwr))
//		pwr = -1;
//	else
//		pwr += off;

//	return format_txpower(pwr);
//}

//static char * print_quality(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int qual;
//	if (iw->quality(ifname, &qual))
//		qual = -1;

//	return format_quality(qual);
//}

//static char * print_quality_max(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int qmax;
//	if (iw->quality_max(ifname, &qmax))
//		qmax = -1;

//	return format_quality_max(qmax);
//}

//static char * print_signal(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int sig;
//	if (iw->signal(ifname, &sig))
//		sig = 0;

//	return format_signal(sig);
//}

//static char * print_noise(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int noise;
//	if (iw->noise(ifname, &noise))
//		noise = 0;

//	return format_noise(noise);
//}

//static char * print_rate(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int rate;
//	if (iw->bitrate(ifname, &rate))
//		rate = -1;

//	return format_rate(rate);
//}

//static char * print_encryption(const struct iwinfo_ops *iw, const char *ifname)
//{
//	struct iwinfo_crypto_entry c = { 0 };
//	if (iw->encryption(ifname, (char *)&c))
//		return format_encryption(NULL);

//	return format_encryption(&c);
//}

//static char * print_hwmodes(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int modes;
//	if (iw->hwmodelist(ifname, &modes))
//		modes = -1;

//	return format_hwmodes(modes);
//}

//static char * print_mbssid_supp(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int supp;
//	static char buf[4];

//	if (iw->mbssid_support(ifname, &supp))
//		snprintf(buf, sizeof(buf), "no");
//	else
//		snprintf(buf, sizeof(buf), "%s", supp ? "yes" : "no");

//	return buf;
//}


static void print_info(const struct iwinfo_ops *iw, const char *ifname)
{
    //	printf("%-9s ESSID: %s\n",
    //		ifname,
    //		print_ssid(iw, ifname));
    printf("          Access Point: %s\n",
           print_bssid(iw, ifname));
    //	printf("          Mode: %s  Channel: %s (%s)\n",
    //		print_mode(iw, ifname),
    //		print_channel(iw, ifname),
    //		print_frequency(iw, ifname));
    //	printf("          Tx-Power: %s  Link Quality: %s/%s\n",
    //		print_txpower(iw, ifname),
    //		print_quality(iw, ifname),
    //		print_quality_max(iw, ifname));
    //	printf("          Signal: %s  Noise: %s\n",
    //		print_signal(iw, ifname),
    //		print_noise(iw, ifname));
    //	printf("          Bit Rate: %s\n",
    //		print_rate(iw, ifname));
    //	printf("          Encryption: %s\n",
    //		print_encryption(iw, ifname));
    //	printf("          Type: %s  HW Mode(s): %s\n",
    //		print_type(iw, ifname),
    //		print_hwmodes(iw, ifname));
    //	printf("          Hardware: %s [%s]\n",
    //		print_hardware_id(iw, ifname),
    //		print_hardware_name(iw, ifname));
    //	printf("          TX power offset: %s\n",
    //		print_txpower_offset(iw, ifname));
    //	printf("          Frequency offset: %s\n",
    //		print_frequency_offset(iw, ifname));
    //	printf("          Supports VAPs: %s\n",
    //		print_mbssid_supp(iw, ifname));
}


static void print_scanlist(const struct iwinfo_ops *iw, const char *ifname)
{
    int i, x, len;
    char buf[IWINFO_BUFSIZE];
    struct iwinfo_scanlist_entry *e;

    if (iw->scanlist(ifname, buf, &len))
    {
        printf("Scanning not possible\n\n");
        return;
    }
    else if (len <= 0)
    {
        printf("No scan results\n\n");
        return;
    }

    for (i = 0, x = 1; i < len; i += sizeof(struct iwinfo_scanlist_entry), x++)
    {
        e = (struct iwinfo_scanlist_entry *) &buf[i];

        //printf("Cell %02d - Address: %s\n",
        //	x,
        //	format_bssid(e->mac));
        printf("          ESSID: %s\n",
               format_ssid(e->ssid));
        //printf("          Mode: %s  Channel: %s\n",
        //	IWINFO_OPMODE_NAMES[e->mode],
        //	format_channel(e->channel));
        //  printf("          Signal: %s  Quality: %s/%s\n",
        ////	format_signal(e->signal - 0x100),
        //	format_quality(e->quality),
        //	format_quality_max(e->quality_max));
        //printf("          Encryption: %s\n\n",
        //	format_encryption(&e->crypto));
    }
}


//static void print_txpwrlist(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int len, pwr, off, i;
//	char buf[IWINFO_BUFSIZE];
//	struct iwinfo_txpwrlist_entry *e;

//	if (iw->txpwrlist(ifname, buf, &len) || len <= 0)
//	{
//		printf("No TX power information available\n");
//		return;
//	}

//	if (iw->txpower(ifname, &pwr))
//		pwr = -1;

//	if (iw->txpower_offset(ifname, &off))
//		off = 0;

//	for (i = 0; i < len; i += sizeof(struct iwinfo_txpwrlist_entry))
//	{
//		e = (struct iwinfo_txpwrlist_entry *) &buf[i];

//		printf("%s%3d dBm (%4d mW)\n",
//			(pwr == e->dbm) ? "*" : " ",
//			e->dbm + off,
//			iwinfo_dbm2mw(e->dbm + off));
//	}
//}


//static void print_freqlist(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int i, len, ch;
//	char buf[IWINFO_BUFSIZE];
//	struct iwinfo_freqlist_entry *e;

//	if (iw->freqlist(ifname, buf, &len) || len <= 0)
//	{
//		printf("No frequency information available\n");
//		return;
//	}

//	if (iw->channel(ifname, &ch))
//		ch = -1;

//	for (i = 0; i < len; i += sizeof(struct iwinfo_freqlist_entry))
//	{
//		e = (struct iwinfo_freqlist_entry *) &buf[i];

//		printf("%s %s (Channel %s)%s\n",
//			(ch == e->channel) ? "*" : " ",
//			format_frequency(e->mhz),
//			format_channel(e->channel),
//			e->restricted ? " [restricted]" : "");
//	}
//}





//static char * lookup_country(char *buf, int len, int iso3166)
//{
//	int i;
//	struct iwinfo_country_entry *c;

//	for (i = 0; i < len; i += sizeof(struct iwinfo_country_entry))
//	{
//		c = (struct iwinfo_country_entry *) &buf[i];

//		if (c->iso3166 == iso3166)
//			return c->ccode;
//	}

//	return NULL;
//}

//static void print_countrylist(const struct iwinfo_ops *iw, const char *ifname)
//{
//	int len;
//	char buf[IWINFO_BUFSIZE];
//	char *ccode;
//	char curcode[3];
//	const struct iwinfo_iso3166_label *l;

//	if (iw->countrylist(ifname, buf, &len))
//	{
//		printf("No country code information available\n");
//		return;
//	}

//	if (iw->country(ifname, curcode))
//		memset(curcode, 0, sizeof(curcode));

//	for (l = IWINFO_ISO3166_NAMES; l->iso3166; l++)
//	{
//		if ((ccode = lookup_country(buf, len, l->iso3166)) != NULL)
//		{
//			printf("%s %4s	%c%c\n",
//				strncmp(ccode, curcode, 2) ? " " : "*",
//				ccode, (l->iso3166 / 256), (l->iso3166 % 256));
//		}
//	}
//}
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <time.h>
// C++


#define MAX_MSG_LEN 16
#define true 1
#define false 0
typedef struct a_MAC
{
    char array_MAC[18];
    int state ;              //1 jest w sieci  0 nie ma
    int state_temp;
};
#define ok     0
#define i_am   1
#define MAC_status 2
#define ON     1
#define OFF    0
#define UNKNOWN 3
void set_bufor (float * bufor, int what)
{
    switch ( what)
    {
    case ok:
        bufor[0]=1;    bufor[1]=0;    bufor[2]=1;
        bufor[3]=0;    bufor[4]=1;    // wysylamy  ze ok
        bufor[5]=0;    bufor[6]=1;    bufor[7]=0;    bufor[8]=1;    bufor[9]=0;    bufor[10]=1;    bufor[11]=0;    bufor[12]=1;    bufor[13]=0;    bufor[14]=1; bufor[15]=0;
        break;
    case i_am:
        bufor[0]=22;    bufor[1]=21;    bufor[2]=202;    bufor[3]=201;    bufor[4]=1;    ///  dodac automatyczne uzupelnianie adresu ip
        bufor[5]=2;    bufor[6]=7;    bufor[7]=0;    bufor[8]=0;    bufor[9]=0;    bufor[10]=0;    bufor[11]=0;    bufor[12]=0;    bufor[13]=0;    bufor[14]=0;    bufor[15]=1;
        break;

    case MAC_status:
        bufor[0] = 44;        bufor[1] = 44; bufor [2] =44;
        break;
    default:

        break;
    }
}

void Send_and_recv (int *gniazdo ,float  bufor[MAX_MSG_LEN], int *max_msg)
{

    if(( send( gniazdo, bufor, max_msg, MSG_DONTWAIT ) ) <= 0 ) // MSG_DONTWAIT
    {
        perror( "send() ERROR" );
        exit( - 1 );
    }

    //bzero( bufor, MAX_MSG_LEN );
    for (int i =0 ; i < MAX_MSG_LEN ; ++i )
    {
        bufor[i]=0;
    }

    if(( recv( gniazdo, bufor, max_msg, 0 ) ) <= 0 )
    {
        perror( "recv() ERROR" );
        exit( - 1 );
    }

} // end Send_and_recv




static void print_assoclist(const struct iwinfo_ops *iw, const char *ifname , struct a_MAC * my_MAC, int many_mac, int *gniazdo, float bufor[  ] , int * max_msg)
{

  //  printf("start \n");
    int i, len;
    char buf[IWINFO_BUFSIZE];
    struct iwinfo_assoclist_entry *e;
    //char *adres_mac = "EC:89:F5:5C:C8:94";

    if (iw->assoclist(ifname, buf, &len))
    {
        printf("No information available\n");
        return;
    }
    else if (len <= 0)
    {
        printf("No station connected\n");
        return;
    }

   // printf("len ma %i \n",len);
    //    for (int k =0 ; k < many_mac; ++k)
    //    {
    //        my_MAC[k].state_now=my_MAC[k].state_temp=OFF;
    //    }

    int counter = len / sizeof(struct iwinfo_assoclist_entry);

    for (int k =0 ; k < many_mac; ++k)
    {
        my_MAC[k].state_temp=0;

        for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry))
        {
            e = (struct iwinfo_assoclist_entry *) &buf[i];

            //            printf("to jest  %s \n" ,format_bssid(e->mac)
            //                   /*format_signal(e->signal),
            //                          format_noise(e->noise),
            //                          (e->signal - e->noise),
            //                          e->inactive*/
            //                   );

            //printf("tu mamy k= %i i %s \n",k,   my_MAC[k].array_MAC);
            //printf("stan k %i = %i \n",k,my_MAC[k].state);

            if (strcmp(  my_MAC[k].array_MAC ,format_bssid(e->mac)) == 0)
            {

                //my_MAC[k].state_now=1;

                if ( my_MAC[k].state==OFF )
                {
                    my_MAC[k].state=ON;
                   set_bufor(bufor , MAC_status);
                    bufor[4]=(float) k;
                    bufor[6]=bufor[7]=(float)1;
                   Send_and_recv(*gniazdo, bufor, *max_msg);
                     printf(" jest  %s \n", my_MAC[k].array_MAC);
                    break;
                }


            }
            else
            {

                ++my_MAC[k].state_temp;
                //                if ( my_MAC[k].state==ON  )
                //                {
                //                        my_MAC[k].state=OFF;
                //                        my_MAC[k].state_now=OFF;
                //                        printf(" odlaczyl sie %s \n", my_MAC[k].array_MAC);
                //                }
            }
        }
        if ( my_MAC[k].state_temp ==counter && my_MAC[k].state==ON  )
        {
            my_MAC[k].state=OFF;

            set_bufor(bufor , MAC_status);
             bufor[4]=(float) k;
             bufor[6]=bufor[7]=(float)0;
            Send_and_recv(*gniazdo, bufor, *max_msg);

          printf(" odl1aczyl sie %s \n", my_MAC[k].array_MAC);
        }
    }
    //		printf("	RX: %-38s  %8d Pkts.\n",
    //			format_assocrate(&e->rx_rate),
    //			e->rx_packets
    //		);

    //		printf("	TX: %-38s  %8d Pkts.\n\n",
    //			format_assocrate(&e->tx_rate),
    //			e->tx_packets
    //		);
   // printf("koniec funkcji \n");

}
int main( int argc, char ** argv )
{
    //        int * test;
    //        int licznik;
    //        std::cin >> licznik;
    //        test = new int [licznik];
    //        for ( int i =0 ; i<licznik; ++i)
    //        {
    //            test[i]=i+2;
    //        }
    //        for ( int i =0 ; i<licznik; ++i)
    //        {
    //            std::cout << " " << test[i]<<std::endl;
    //        }
    //        std::cin >> licznik;
    //        std::cout << " zwalniam \n";
    //        delete [] test;
    if (argc <3)
    {   printf("\e[0;31m");//a teraz na czerwono
        printf ( "Try: \e[0;1m  %c  \e[0;33m [ip_adres] [port]\n",argv[0]);
        printf("\e[0;0m");//powrot do normy
        return 0;
    }

    int i;
    char *p;
    const struct iwinfo_ops *iw;
    glob_t globbuf;



    iw = iwinfo_backend("wlan0");
    if (!iw)
    {
        fprintf(stderr, "No such wireless device: %s\n", argv[1]);
        return 1;
    }


    int go_while = true;
    int v_delay=1;
    int many_mac = 0;
    //struct a_MAC *my_MAC  ;    // trzyma adresy mac do sprawdzania oraz jego maszyne stanu
    struct a_MAC my_MAC[10];
    struct sockaddr_in serwer;
    int gniazdo;
    float bufor[ MAX_MSG_LEN ];
    int max_msg = MAX_MSG_LEN*sizeof(float);

    bzero( & serwer, sizeof( serwer ) );
    //bzero( bufor, MAX_MSG_LEN );
    for (int i =0 ; i < MAX_MSG_LEN ; ++i )
    {
        bufor[i]=0;
    }
    const char * ip = argv[ 1 ];
    uint16_t port = atoi( argv[ 2 ] );


    serwer.sin_family = AF_INET;
    serwer.sin_port = htons( port );
    if( inet_pton( AF_INET, ip, & serwer.sin_addr ) <= 0 )
    {
        perror( "Wrong ip adres\n" );
        exit( - 1 );
    }

    if(( gniazdo = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
    {
        perror( "socket() ERROR" );
        exit( - 1 );
    }

    socklen_t len = sizeof( serwer );
    if( connect( gniazdo,( struct sockaddr * ) & serwer, len ) < 0 )
    {
        perror( "connect() ERROR" );
        exit( - 1 );
    }
    ////////////////////////////////////////////    wysylamy  wiadomosc ze chcemy sprawdzac czy sa dane mac i  w sieci
    set_bufor ( bufor, i_am );

    if(( send( gniazdo, bufor, max_msg, MSG_DONTWAIT ) ) <= 0 ) // MSG_DONTWAIT
    {
        perror( "send() ERROR" );
        exit( - 1 );
    }

    if(( recv( gniazdo, bufor, max_msg, 0 ) ) <= 0 )
    {
        perror( "recv() ERROR" );
        exit( - 1 );
    }
//    printf("  bufor ma : ");
//    for (int i =0 ; i < MAX_MSG_LEN ; ++i )
//    {
//       printf("  %f", bufor[i]);
//    }
//    printf("  \n ");
    if (bufor[0]==bufor[1] && bufor[2]==bufor[3] && bufor[0] ==33  )
    {
        v_delay =(int)bufor[9];
        many_mac=(int)bufor[7];

            /////     printf(" alokuje pamiec  %i \n ",many_mac);
        //        my_MAC = ( struct a_MAC * ) malloc( many_mac * sizeof( struct  a_MAC* ) );
           //     printf(" udało sie zaalokowac  %i \n ",many_mac);
    }

    //////////////////   wysy&#322;amy ok  ze jestesmy gotowi do odbioru adresَw
    for (int i =0 ; i < many_mac; ++i)
    {
        set_bufor ( bufor, ok );

        if(( send( gniazdo, bufor, max_msg, MSG_DONTWAIT ) ) <= 0 ) // MSG_DONTWAIT
        {
            perror( "send() ERROR" );
            exit( - 1 );
        }

        if(( recv( gniazdo, bufor, max_msg, 0 ) ) <= 0 )
        {
            perror( "recv() ERROR" );
            exit( - 1 );
        }
        if (bufor[0]==34 && bufor[1]==34 && bufor[2] ==0 && bufor[3]==(float)i  )
        {

            my_MAC[i].array_MAC[0]=bufor[4] ;
            my_MAC[i].array_MAC[1]=bufor[5] ;
            my_MAC[i].array_MAC[2]=':';
            my_MAC[i].array_MAC[3]=bufor[6] ;
            my_MAC[i].array_MAC[4]=bufor[7] ;
            my_MAC[i].array_MAC[5]=':';
            my_MAC[i].array_MAC[6]=bufor[8] ;
            my_MAC[i].array_MAC[7]=bufor[9] ;
            my_MAC[i].array_MAC[8]=':';
            my_MAC[i].array_MAC[9]=bufor[10] ;
            my_MAC[i].array_MAC[10]=bufor[11] ;
            my_MAC[i].array_MAC[11]=':';
            my_MAC[i].array_MAC[12]=bufor[12] ;
            my_MAC[i].array_MAC[13]=bufor[13] ;
            my_MAC[i].array_MAC[14]=':';
            my_MAC[i].array_MAC[15]=bufor[14] ;
            my_MAC[i].array_MAC[16]=bufor[15] ;

            my_MAC[i].state=0;   // stan kazdego na poczatku ustawiany jest na 0  - nie ma go w sieci




        }

    }
    int licznik=0;
    do {

        ++licznik;
        // printf ("jestem w do %i\n",licznik);
      print_assoclist(iw, "wlan0" , &my_MAC, many_mac, &gniazdo, &bufor, &max_msg);

       //printf ("wywolalem assoclist \n");
        //usleep(v_delay);
        sleep(v_delay);
       //printf ("koniec pauzy %i\n", v_delay );
    } while(go_while);
    shutdown( gniazdo, SHUT_RDWR );




    // scanf ("%i",&many_mac);


    //    print_assoclist(iw, "wlan0");
    // print_scanlist(iw, "wlan0");
    // print_info(iw,"wlan0");
    iwinfo_finish();

    return 0;
}
