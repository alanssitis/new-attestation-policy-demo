link-gen: tidy bin
	go build -o ./bin/$@

.PHONY: tidy
tidy:
	go mod tidy

bin:
	mkdir -p bin

clean:
	rm -rf bin
