package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/mholt/archiver"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	deviceName      string
	outputFile      string
	filter          string
	pidFile         string
	durationMinutes int
	snapshotLen     uint32 = 4096
	promiscuous     bool   = false
	err             error
	timeout         time.Duration = -1 * time.Second
	handle          *pcap.Handle
	f               *os.File
	zip             bool
	debug           bool
)

func init() {
	flag.StringVar(&deviceName, "i", "eth0", "interface")
	flag.StringVar(&outputFile, "o", "out.pcap", "out file")
	flag.StringVar(&filter, "f", "udp and port 5060", "filter")
	flag.IntVar(&durationMinutes, "r", 1, "rotate out file every minutes")
	flag.BoolVar(&zip, "z", false, "zip rotated file")
	flag.BoolVar(&debug, "debug", false, "debug")
	flag.StringVar(&pidFile, "p", "/var/run/sniff.pid", "pid file")
}

func copy(src string, dst string) {
	data, _ := ioutil.ReadFile(src)
	ioutil.WriteFile(src, nil, 0644)
	go func() {
		ioutil.WriteFile(dst, data, 0644)
		archiver.Zip.Make(dst+".zip", []string{dst})
		os.Remove(dst)
	}()
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	writePidFile()

	for {
		f, _ := os.Create(outputFile)
		writer := pcapgo.NewWriter(f)
		writer.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)

		// Open the device for capturing
		handle, err = pcap.OpenLive(deviceName, int32(snapshotLen), promiscuous, timeout)
		if err != nil {
			fmt.Printf("Error opening device %s: %v", deviceName, err)
			os.Exit(1)
		}

		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		start := time.Now()
		fmt.Printf("sniff on %s", deviceName)

		for packet := range packetSource.Packets() {
			if debug {
				fmt.Println(packet)
			}

			writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

			if time.Since(start) > time.Minute*time.Duration(durationMinutes) {
				break
			}
		}

		now := time.Now().Add(-1 * time.Minute * time.Duration(durationMinutes))
		unixTimestamp := now.Format(time.RFC3339)

		f.Close()
		handle.Close()

		copy(outputFile, outputFile+"."+unixTimestamp)
	}
}

func writePidFile() error {
	// Read in the pid file as a slice of bytes.
	if piddata, err := ioutil.ReadFile(pidFile); err == nil {
		// Convert the file contents to an integer.
		if pid, err := strconv.Atoi(string(piddata)); err == nil {
			// Look for the pid in the process list.
			if process, err := os.FindProcess(pid); err == nil {
				// Send the process a signal zero kill.
				if err := process.Signal(syscall.Signal(0)); err == nil {
					// We only get an error if the pid isn't running, or it's not ours.
					return fmt.Errorf("pid already running: %d", pid)
				}
			}
		}
	}
	// If we get here, then the pidfile didn't exist,
	// or the pid in it doesn't belong to the user running this app.
	return ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0664)
}
