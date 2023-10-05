LaTeXiT-metadata-macos: LaTeXiT-metadata-macos.o
	clang++ -std=c++11 -lstdc++ -fobjc-link-runtime -framework Foundation -framework CoreGraphics -framework Quartz -lz -o LaTeXiT-metadata-macos LaTeXiT-metadata-macos.o
	
LaTeXiT-metadata-macos.o : LaTeXiT-metadata-macos.mm
	clang++ -c -std=c++11 LaTeXiT-metadata-macos.mm

clean :
	rm LaTeXiT-metadata-macos LaTeXiT-metadata-macos.o
