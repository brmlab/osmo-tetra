#!/usr/bin/env python2

from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.filter import pfb
import osmosdr
import tetra_demod

class top_block(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self)

        ##################################################
        # Variables
        ##################################################
        self.symbol_rate = symbol_rate = 18000
        self.samp_per_sym = samp_per_sym = 2
        self.channel_width = channel_width = 25e3
        self.chans = chans = 36*2  # must be multiple of 36
        self.sample_rate = sample_rate = chans * channel_width
        self.out_samp_rate = out_samp_rate = symbol_rate*samp_per_sym
        self.offset = offset = -73e3
        self.lowpass = lowpass = 17.5e3
        self.fnames = '/home/test/tetra-tmp/fifo'

        #### LIST OF DEMODULATED CHANNELS
        # numbered from leftmost to rightmost
        self.selected = [ 6,7,8,9,12,13,14,16,17,19,20,21,23,24,26,31,32,33,34,35,38,42,43,44,45,46,47,50,52,53,55,56,61,62,69,70]

        ##################################################
        # Blocks
        ##################################################

        # Common for all targets
        #self.source = osmosdr.source( args="rtl_tcp=radio-tetra.brm:1234")
        self.source = osmosdr.source()
        self.source.set_sample_rate(sample_rate)
        self.source.set_center_freq(424.065e6, 0)
        self.source.set_freq_corr(0, 0)
        self.source.set_dc_offset_mode(0, 0)
        self.source.set_iq_balance_mode(0, 0)
        self.source.set_gain_mode(0, 0)
        self.source.set_gain(31, 0)
        self.source.set_if_gain(20, 0)
        self.source.set_bb_gain(20, 0)
        self.source.set_antenna("", 0)
        self.source.set_bandwidth(0, 0)

        self.channelizer = pfb.channelizer_ccf(
              chans,
              (),
              1.0,
              100)

        self.channelizer.set_channel_map((range(chans/2, chans)+range(0,chans/2)))

        # Generate per-target blocks
        self.sinks = list()
        self.demods = list()
        self.resamplers = list()
        sel = 1
        for i in range(chans):
            if i in self.selected:
                self.resamplers.append(filter.rational_resampler_ccc(
                    interpolation=36,
                    decimation=25,
                    taps=None,
                    fractional_bw=None,
                ))

                self.demods.append(tetra_demod.demod())
                self.sinks.append(blocks.file_sink(gr.sizeof_float, "%s/floats%d" % (self.fnames, sel)))
                self.connect((self.channelizer, i), (self.resamplers[i], 0))
                self.connect((self.resamplers[i], 0),  (self.demods[i], 0),  (self.sinks[i], 0))
                sel = sel + 1
                print "Enabled channel %d" % i
            else:
                self.resamplers.append(None)
                self.demods.append(None)
                self.sinks.append(blocks.null_sink(gr.sizeof_gr_complex*1))
                self.connect((self.channelizer, i), (self.sinks[i], 0))
                print "Skipping channel %d" % i

        # Connections
        self.connect((self.source, 0), (self.channelizer, 0))


if __name__ == '__main__':
    tb = top_block()
    tb.run()

