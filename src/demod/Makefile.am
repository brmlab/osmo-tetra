#
# Copyright 2001,2006,2008,2009 Free Software Foundation, Inc.
# 
# This file is part of GNU Radio
# 
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

ACLOCAL_AMFLAGS = -I config
AUTOMAKE_OPTIONS = foreign

include $(top_srcdir)/Makefile.common


SUBDIRS = python apps config grc

export pythondir

install-data-hook:
	@if ! python -c "import gnuradio" > /dev/null 2>&1; then\
		printf "\n*** Post-Install Message ***\
		\nWarning: python could not find the gnuradio module.\
		\nMake sure that $${pythondir} is in your PYTHONPATH\n\n";\
	fi


