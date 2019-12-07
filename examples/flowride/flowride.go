package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"

	"github.com/streadway/amqp"
)

type FlowrideConfig struct {
	AMQPURL         string   //url for rabbitmq with vhost user and pas
	DPDKArgs        []string // args array for DPDK {"-w card", "-w othercard"}
	CPUList         string   // "0-15"
	InPort          int      // the input dpdk card port
	OutPort         int      // the output dpdk card port
	FlowTimeoutSecs int      // seconds to timeout a flow due to inactivity
	ExportSecs      int      // seconds to export to the message queue
	StatusSecs      int      // seconds to print the status line
	RabbitHeartbeat int      // seconds for heartbeat between cli and srv
}

func NewFlowrideConfig() *FlowrideConfig {
	return &FlowrideConfig{
		AMQPURL:         "REQUIRED",
		DPDKArgs:        []string{"REQUIRED"},
		CPUList:         "0-10",
		InPort:          0,
		OutPort:         1,
		FlowTimeoutSecs: 5,
		ExportSecs:      5,
		StatusSecs:      5,
		RabbitHeartbeat: 20,
	}
}

func (f *FlowrideConfig) FromFile(a string) error {
	b, err := ioutil.ReadFile(a)
	if err != nil {
		return err
	}
	json.Unmarshal(b, f)
	return nil
}

//a pure flowspec (no state) that is used also
//as key to the dictionary of active flows
//time started is not part of the string that matches
//on the dictionary
type flowspec struct {
	src         net.IP
	dst         net.IP
	sport       uint16
	dport       uint16
	proto       string
	timeStarted time.Time
}

//an inclomplete flow, wrapping the above with state
//of packets and bytes and their difference since last export.
type incflowspec struct {
	flowspec
	npkts    uint64
	bytes    uint64
	dnpkts   uint64
	dplen    uint64
	tcpFlags uint8
	icmpType uint8
	tosByte  uint8
}

//a completed flow that wraps the above with a boolean
//on how it closed.
type exflowspec struct {
	incflowspec
	reset     bool
	active    bool
	timeEnded time.Time
}

const (
	ADD = int(iota)
	DEL
	LEN
	EXPORT
	GETEXPORTED
)

type flowcomm struct {
	id       int
	spec     flowspec
	link     flowlink
	dir      int
	num      uint64
	entries  string
	ftime    time.Time
	tflags   types.TCPFlags
	exspec   exflowspec
	exported string
	plen     uint
	icmpType uint8
	tosByte  uint8
}

type flowmap struct {
	fm   map[string]flowlink
	expf []exflowspec
	ich  chan flowcomm
	och  chan flowcomm
	done chan struct{}
}

const ( // directions , normal or reverse
	NORMAL = iota
	REVERSE
)

func NewFlowMap() *flowmap {
	fm := &flowmap{
		fm:   make(map[string]flowlink),
		expf: make([]exflowspec, 0),
		ich:  make(chan flowcomm),
		och:  make(chan flowcomm),
		done: make(chan struct{}),
	}
	go func(fm *flowmap) {
		var (
			fl        flowlink
			ok1, ok2  bool
			direction int
		)
		for {
			select {
			case command := <-fm.ich:
				switch command.id {
				case ADD:
					fspec := command.spec
					tflags := command.tflags
					time := command.ftime
					plen := command.plen
					itype := command.icmpType
					tos := command.tosByte
					direction = NORMAL
					ok1 = false
					ok2 = false
					fl, ok1 = fm.fm[fspec.Key()]
					if !ok1 {
						fl, ok2 = fm.fm[fspec.InvKey()]
						if ok2 {
							direction = REVERSE
						}
					}
					if ok1 || ok2 { //we found it in one of the two directions
						if tflags&types.TCPFlagRst == types.TCPFlagRst { //close it straight due to RST
							fl.Close(tflags, direction)
						} else if (tflags&types.TCPFlagFin) == types.TCPFlagFin && direction == REVERSE { //close the with proper FIN termination
							fl.Close(tflags, direction)
						} else if tflags&types.TCPFlagFin == types.TCPFlagSyn && direction == NORMAL { // we are getting into a FIN termination
							fl.Update(time, tflags, plen, direction)
						} else if tflags&types.TCPFlagSyn == types.TCPFlagSyn {
							//fmt.Printf("disregarding double sin on started flow %s\n", fl)
						} else if tflags&types.TCPFlagAck == types.TCPFlagAck {
							fl.Update(time, tflags, plen, direction)
						} else if fspec.proto == "UDP" {
							fl.Update(time, tflags, plen, direction)
						} else if fspec.proto == "ICMP" {
							fl.Update(time, tflags, plen, direction)
						}
					} else if !ok1 && !ok2 { //add it , cause it doesn't exist in any direction
						if fspec.proto == "TCP" && tflags&types.TCPFlagSyn == types.TCPFlagSyn {
							//fmt.Printf("starting new flow with spec %s\n", fspec)
							fm.fm[fspec.Key()] = NewFlow(fspec, fm, plen, itype, tos, tflags)
						} else if fspec.proto == "TCP" && tflags&types.TCPFlagAck == types.TCPFlagAck {
							//fmt.Printf("ack for %s disregarded\n")
						} else if fspec.proto == "UDP" {
							fm.fm[fspec.Key()] = NewFlow(fspec, fm, plen, itype, tos, tflags)
						} else if fspec.proto == "ICMP" {
							fm.fm[fspec.Key()] = NewFlow(fspec, fm, plen, itype, tos, tflags)
						}
					}

				case DEL:
					fspec := command.spec
					if _, ok := fm.fm[fspec.Key()]; ok {
						//close(fl)
						delete(fm.fm, fspec.Key())
					} else if _, ok := fm.fm[fspec.InvKey()]; ok {
						delete(fm.fm, fspec.InvKey())
					}

				case LEN:
					rep := flowcomm{
						num: uint64(len(fm.fm)),
					}
					fm.och <- rep
				case EXPORT:
					fspec := command.exspec
					fm.expf = append(fm.expf, fspec)
				case GETEXPORTED:
					var buf bytes.Buffer
					for _, val := range fm.expf {
						buf.WriteString(fmt.Sprintf("%s\n", val))
					}
					fm.expf = make([]exflowspec, 0)
					rep := flowcomm{
						exported: buf.String(),
					}
					fm.och <- rep
				}
			case <-fm.done:
				log.Printf("flowmap closing")
				return
			}
		}
	}(fm)
	return fm
}

func (f *flowmap) DeleteFlow(fspec flowspec) {
	comm := flowcomm{
		id:   DEL,
		spec: fspec,
	}
	f.ich <- comm
}

func (f *flowmap) Size() uint64 {
	comm := flowcomm{
		id: LEN,
	}
	f.ich <- comm
	rep := <-f.och
	return rep.num
}

func (f *flowmap) AddOrUpdateFlow(fspec flowspec, time time.Time, tflags types.TCPFlags, plen uint, icmpType uint8, tosByte uint8) {
	comm := flowcomm{
		id:       ADD,
		spec:     fspec,
		ftime:    time,
		tflags:   tflags,
		plen:     plen,
		icmpType: icmpType,
		tosByte:  tosByte,
	}
	f.ich <- comm
}

func (f *flowmap) Export(fl exflowspec) {
	comm := flowcomm{
		id:     EXPORT,
		exspec: fl,
	}
	f.ich <- comm
}

func (f *flowmap) GetExported() string {
	//theloume afto na kataferei na gyrisei grigora.
	//kata protimish served apo allo goroutine oxi apo to flowmap.
	comm := flowcomm{
		id: GETEXPORTED,
	}
	f.ich <- comm
	rep := <-f.och
	return rep.exported
}

type flowCommandId uint8

const (
	FCommUpdate = flowCommandId(iota)
	FCommDelete
)

type flowCommand struct {
	id    flowCommandId
	t     time.Time
	flags types.TCPFlags
	plen  uint
}

// apart from the flowspec which is the key on the hashmap
// this struct also keeps the number of packets
// and the number of bytes as well as their dxxxx variants.
// The d variants are differenctial and are zeroed out on every
// export. they should only show they cumulative counts between
// exports.
type flowctx struct {
	fspec     flowspec
	ltime     time.Time
	flags     types.TCPFlags //this will record all the bits set in all the tcp flags of the flow
	tosByte   uint8          // the tos of the first byte if any
	icmpType  uint8          // icmp type of the first byte if any
	npkts     uint64
	dnpkts    uint64
	plen      uint64
	dplen     uint64
	finState  bool
	cchan     chan flowCommand
	killt     *time.Ticker
	statust   *time.Ticker
	parentmap *flowmap
}

type flowlink chan flowCommand

func (f flowctx) String() string {
	return fmt.Sprintf("%s [atime:%s] [npkts:%d]", f.fspec.String(), f.ltime, f.npkts)
}

func (f flowspec) String() string {
	return fmt.Sprintf("flow\tfrom [%s]\tto [%s]\tsport [%d]\tdport[%d]\tstarted[%s]\tproto[%s]",
		f.src, f.dst, f.sport, f.dport, f.timeStarted, f.proto)
}

func (f flowspec) Key() string {
	return fmt.Sprintf("%s-%s-%d-%d-%s",
		f.src, f.dst, f.sport, f.dport, f.proto)
}

func (f flowspec) InvKey() string {
	return fmt.Sprintf("%s-%s-%d-%d-%s",
		f.dst, f.src, f.dport, f.sport, f.proto)
}

func (f exflowspec) VerboseString() string {
	return fmt.Sprintf("[active:%v] flow\tfrom [%s]\tto [%s]\tsport [%d]\tdport[%d]\tstarted[%s]\tended[%s]\tnpkts[%d]\tbytes[%d]\treset?[%v]\tproto[%s]\tTCPFlags[%d]\tICMPtype[%d]\tTOS[%d]\tdpkts[%d]\tdbytes[%d]",
		f.active, f.src, f.dst, f.sport, f.dport, f.timeStarted, f.timeEnded, f.npkts, f.bytes, f.reset, f.proto, f.tcpFlags, f.icmpType, f.tosByte, f.dnpkts, f.dplen)
}

func rststring(a bool, active bool) string {
	if active {
		return "x"
	}
	if a {
		return "RST"
	} else {
		return "FIN"
	}
}

func actstring(active bool) string {
	if active {
		return "ACTIVE"
	}
	return "CLOSED"
}

func (f exflowspec) String() string {
	return fmt.Sprintf("%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d",
		f.timeStarted.UnixNano(), f.proto, actstring(f.active), rststring(f.reset, f.active), f.src, f.dst, f.sport, f.dport, f.npkts, f.bytes, f.tcpFlags, f.icmpType, f.tosByte, f.dnpkts, f.dplen, f.timeEnded.UnixNano())
}

func (f incflowspec) String() string {
	return fmt.Sprintf("[inc] %s flow\tfrom [%s]\tto [%s]\tsport [%d]\tdport[%d]\ttstarted[%s]\tnpkts[%d]\tbytes[%d]\tTCPFlags[%d]\tICMPType[%d]\tTOS[%d]",
		f.proto, f.src, f.dst, f.sport, f.dport, f.timeStarted, f.npkts, f.bytes, f.tcpFlags, f.icmpType, f.tosByte)
}

func (f flowlink) Update(time time.Time, fl types.TCPFlags, plen uint, direction int) {
	go func() {
		f <- flowCommand{
			id:    FCommUpdate,
			t:     time,
			flags: fl,
			plen:  plen,
		}
	}()
}

func (f flowlink) Close(fl types.TCPFlags, direction int) {
	go func() { //do it async cause i don't want to block
		f <- flowCommand{
			id:    FCommDelete,
			flags: fl,
		}
	}()
}

func Start(f *flowctx) {
	var updatedInTimeRange bool
	updatedInTimeRange = true
	f.killt = time.NewTicker(time.Duration(fconfig.ExportSecs) * time.Second)
	f.statust = time.NewTicker(time.Duration(fconfig.StatusSecs) * time.Second)
	defer func() { //before we die notify our parent dictionary
		f.parentmap.DeleteFlow(f.fspec)
		f.killt.Stop()
		f.statust.Stop()
	}()
	for {
		select {

		case <-f.killt.C:
			//timer expired
			//fmt.Printf("expiring flow %s after 1 minute\n", f)
			if updatedInTimeRange {
				updatedInTimeRange = false
			} else {
				expf := atomic.LoadUint64(&expiredflows)
				atomic.StoreUint64(&expiredflows, expf+1)
				//stephen observed that udp flows were never closing. this should fix
				//for all flows
				exflow := exflowspec{
					incflowspec{
						f.fspec,
						f.npkts,
						f.plen,
						f.dnpkts,
						f.dplen,
						uint8(f.flags),
						f.icmpType,
						f.tosByte,
					},
					true,
					false, //active?
					time.Now(),
				}
				//XXX set bytes here
				//f.exFlows.Add(exflow)
				f.parentmap.Export(exflow)

				return
			}
		case <-f.statust.C:
			exflow := exflowspec{
				incflowspec{
					f.fspec,
					f.npkts,
					f.plen,
					f.dnpkts,
					f.dplen,
					uint8(f.flags),
					f.icmpType,
					f.tosByte,
				},
				false,
				true, //active?
				time.Now(),
			}
			// Now zero out the differential counters
			f.dnpkts = 0
			f.dplen = 0
			//XXX set bytes here
			//f.exFlows.Add(exflow)
			f.parentmap.Export(exflow)

		case comm := <-f.cchan:
			switch comm.id {
			case FCommUpdate:
				f.ltime = comm.t
				f.flags |= comm.flags //this will record the current flagset on the older ones.
				f.npkts = f.npkts + 1
				f.plen = f.plen + uint64(comm.plen)
				// update the differential counters
				f.dnpkts = f.dnpkts + 1
				f.dplen = f.dplen + uint64(comm.plen)
				updatedInTimeRange = true
				if (f.flags & types.TCPFlagFin) == types.TCPFlagFin { // we are getting into fin
					f.finState = true
				}
			case FCommDelete:
				reseted := false
				//fmt.Printf("deleting flow %s due to command\n", f)
				stopf := atomic.LoadUint64(&stoppedflows)
				atomic.StoreUint64(&stoppedflows, stopf+1)
				//stoppedflows = stoppedflows + 1 //XXX: ATOMIC HERE
				f.flags |= comm.flags
				if (f.flags & types.TCPFlagFin) == types.TCPFlagFin {
					//finflows = finflows + 1
					finf := atomic.LoadUint64(&finflows)
					atomic.StoreUint64(&finflows, finf+1)
				} else if (f.flags & types.TCPFlagRst) == types.TCPFlagRst { //close the flow
					//rstflows = rstflows + 1
					rstf := atomic.LoadUint64(&rstflows)
					atomic.StoreUint64(&rstflows, rstf+1)
					reseted = true
				}
				exflow := exflowspec{
					incflowspec{
						f.fspec,
						f.npkts,
						f.plen,
						f.dnpkts,
						f.dplen,
						uint8(f.flags),
						f.icmpType,
						f.tosByte,
					},
					reseted,
					false, //active?
					time.Now(),
				}
				//XXX set bytes here
				//f.exFlows.Add(exflow)
				f.parentmap.Export(exflow)
				return
			}
		}
	}
}

func NewFlow(fspec flowspec, pmap *flowmap, plen uint, icmpType uint8, tosByte uint8, tflags types.TCPFlags) flowlink {
	cchan := make(flowlink)
	fspec.timeStarted = time.Now()
	fl := &flowctx{
		fspec:     fspec,
		ltime:     fspec.timeStarted,
		cchan:     cchan,
		flags:     tflags,
		npkts:     1,
		plen:      uint64(plen),
		dnpkts:    1,
		dplen:     uint64(plen),
		finState:  false,
		parentmap: pmap,
		icmpType:  icmpType,
		tosByte:   tosByte,
	}

	startf := atomic.LoadUint64(&startedflows)
	atomic.StoreUint64(&startedflows, startf+1)
	//startedflows = startedflows + 1
	go Start(fl)
	return cchan
}

// Constants are taken from paper:
// Huong T. T., Thanh N. H. "Software defined networking-based one-packet DDoS mitigation architecture"//
// Proceedings of the 11th International Conference on Ubiquitous Information Management and Communication. – ACM, 2017. – С. 110.
const (
	monitoringWindow = 6  // 6s - expiration time of flow in a table
	size2InPow       = 28 // 2**size2InPow will be size of a table
	// size is made a pow of 2 to make & instead of %, it is faster
	size                    = uint32(1 << size2InPow)  // table size
	iatThreshold            = float64(0.9)             // when iat > iatThreshold, we consider DDoS is going
	ppfThreshold            = float64(0.8)             // when ppf > ppfThreshold, we consider DDoS is going
	bitsForTime             = 14                       //time takes 14 last bits of flow record
	timeStampMask           = ((1 << bitsForTime) - 1) // 14 last bits mask for timestamp
	getNumOfPacketsMask     = (3 << bitsForTime)       // 2 1st bits mask for num of packets
	timeShiftToGetSeconds   = 30                       // pow(2, 30) is approximately 1e9
	iatValueNanos           = 200000                   // 200 us converted to nanoseconds
	ddosCalculationInterval = 5 * time.Millisecond     // interval to recount ddos metrics
	// if it is large, reaction on ddos will be slow, if it is small, it will
	// slow down the work of handlers due to concurrent access
)

var (
	fconfig *FlowrideConfig
	// flowTable stores number of packets in flow, it takes
	// 2 first bits from uint16,
	// time of last packet is stored in seconds and
	// takes 14 last bits of uint16
	flowTable           [size]uint16
	numOfFlows          = int32(1)
	numOfOnePktFlows    = int32(0)
	packetsWithSmallIAT = int64(0) // number of packets with small
	// inter-arrival time (less than iatValueNanos)
	allPackets   = int64(1)
	lastTime     = time.Now().UnixNano() // time of last handled packet
	expiredflows uint64
	stoppedflows uint64
	rstflows     uint64
	finflows     uint64
	startedflows uint64
	totalPackets uint64
)

func flowHash(srcAddr []byte, srcAddrLen int, srcPort uint32) uint32 {
	h := fnv.New32()
	h.Write(srcAddr)
	return (h.Sum32() + srcPort) & (size - 1)
}

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

// Main function for constructing packet processing graph.
func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: ./flowride jsonConfig")
	}
	fconfig = NewFlowrideConfig()
	e := fconfig.FromFile(os.Args[1])
	if e != nil {
		log.Fatalf("error parsing config:%s", e)
	}
	// Init YANFF system at requested number of cores.
	config := flow.Config{
		CPUList:  fconfig.CPUList,
		DPDKArgs: fconfig.DPDKArgs,
		LogType:  common.Debug,
	}

	CheckFatal(flow.SystemInit(&config))
	fm := NewFlowMap()
	//exf := NewExportedFlows()
	inputFlow, err := flow.SetReceiver(uint16(fconfig.InPort))
	CheckFatal(err)
	CheckFatal(flow.SetHandlerDrop(inputFlow, getHanderFunc(fm), nil))
	CheckFatal(flow.SetSender(inputFlow, uint16(fconfig.OutPort)))
	go printMap(fm)
	go publishFlows(fm)
	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}

func getHanderFunc(fmap *flowmap) func(*packet.Packet, flow.UserContext) bool {
	return func(pkt *packet.Packet, context flow.UserContext) bool {
		var (
			pktTCP   *packet.TCPHdr
			pktUDP   *packet.UDPHdr
			pktICMP  *packet.ICMPHdr
			src      net.IP
			dst      net.IP
			sport    uint16
			dport    uint16
			flags    types.TCPFlags
			protostr string
			pktlen   uint
			icmpType uint8
			tosByte  uint8
		)

		/*PACKET COUNT
		curpkt := atomic.LoadUint64(&totalPackets)
		atomic.StoreUint64(&totalPackets, curpkt+1)
		*/

		pktIPv4, pktIPv6, _ := pkt.ParseAllKnownL3CheckVLAN()
		if pktIPv4 != nil {
			pktTCP, pktUDP, pktICMP = pkt.ParseAllKnownL4ForIPv4()
			src = net.IP{byte(pktIPv4.SrcAddr), byte(pktIPv4.SrcAddr >> 8), byte(pktIPv4.SrcAddr >> 16), byte(pktIPv4.SrcAddr >> 24)}
			dst = net.IP{byte(pktIPv4.DstAddr), byte(pktIPv4.DstAddr >> 8), byte(pktIPv4.DstAddr >> 16), byte(pktIPv4.DstAddr >> 24)}
			pktlen = pkt.GetPacketLen()
		} else if pktIPv6 != nil {
			pktTCP, pktUDP, pktICMP = pkt.ParseAllKnownL4ForIPv6()
			s := pktIPv6.SrcAddr
			src = net.IP{s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]}
			d := pktIPv6.DstAddr
			dst = net.IP{d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]}
			pktlen = pkt.GetPacketLen()
		}
		if pktTCP != nil {
			sport = uint16(packet.SwapBytesUint16(pktTCP.SrcPort))
			dport = uint16(packet.SwapBytesUint16(pktTCP.DstPort))
			flags = pktTCP.TCPFlags
			protostr = "TCP"
		} else if pktUDP != nil {
			sport = uint16(packet.SwapBytesUint16(pktUDP.SrcPort))
			dport = uint16(packet.SwapBytesUint16(pktUDP.DstPort))
			protostr = "UDP"
		} else if pktICMP != nil {
			protostr = "ICMP"
			icmpType = uint8(pktICMP.Type)
		}

		fspec := flowspec{
			src:   src,
			dst:   dst,
			sport: sport,
			dport: dport,
			proto: protostr,
		}
		// fmt.Printf("trying for :%v %v\n", fspec, flags)
		fmap.AddOrUpdateFlow(fspec, time.Now(), flags, pktlen, icmpType, tosByte)
		return true
	}
}
func printMap(fm *flowmap) {
	for {

		startf := atomic.LoadUint64(&startedflows)
		stopf := atomic.LoadUint64(&stoppedflows)
		rstf := atomic.LoadUint64(&rstflows)
		finf := atomic.LoadUint64(&finflows)
		expf := atomic.LoadUint64(&expiredflows)
		totpkt := atomic.LoadUint64(&totalPackets)
		fmt.Printf("Current %d flows [started:%d] [stopped:%d (RST:%d FIN:%d)] [expired:%d] [totpkt:%d]\n", fm.Size(), startf, stopf, rstf, finf, expf, totpkt)
		// fmt.Printf("Current XXX flows [started:%d] [stopped:%d (RST:%d FIN:%d)] [expired:%d]\n", startf, stopf, rstf, finf, expf)
		time.Sleep(5 * time.Second)
	}
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(err)
	}
}

func publishFlows(cf *flowmap) {
	nretries := 0
	totmsgs := 0
	rabbitConfig := amqp.Config{
		Heartbeat: time.Duration(fconfig.RabbitHeartbeat) * time.Second,
	}
retry:
	if nretries > 5 {
		log.Fatalf("maximum retry number exceeded. can't publish flows")
	}
	conn, err := amqp.DialConfig(fconfig.AMQPURL, rabbitConfig)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()
	//we will nonblockingly select on this guy too  on the main loop
	errnotify := conn.NotifyClose(make(chan *amqp.Error, 6)) //XXX See: https://github.com/streadway/amqp/issues/254 for the buffered chan here.
	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()
	args := make(amqp.Table)
	q, err := ch.QueueDeclare(
		"",
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		args,  // arguments
	)
	failOnError(err, "Failed to declare a queue")
	tick := time.NewTicker(time.Duration(fconfig.ExportSecs) * time.Second)
	for {
		select {
		case <-tick.C:
			alldata := cf.GetExported()
			t1 := time.Now()
			err = ch.Publish(
				"xflow", // exchange
				q.Name,  // routing key
				false,   // mandatory
				false,   // immediate
				amqp.Publishing{
					ContentType:  "text/plain",
					Body:         []byte(alldata),
					DeliveryMode: amqp.Transient,
				})
			if err != nil {
				log.Printf("[error] Failed to publish a message:%s", err)
				ch.Close()
				conn.Close()
				nretries++
				time.Sleep(5 * time.Second)
				goto retry
			} else {
				nretries = 0 //reset the retry counter
				totmsgs++
				fmt.Printf("[%v] Published to mq in %v totmsgs:%d strlen:%d\n", time.Now(), time.Since(t1), totmsgs, len(alldata))
			}
		case e := <-errnotify:
			log.Printf("[error] channel notification error:%s. tearing down the connection", e)
			ch.Close()
			conn.Close()
			nretries++
			time.Sleep(5 * time.Second)
			goto retry
		}
	}
}
