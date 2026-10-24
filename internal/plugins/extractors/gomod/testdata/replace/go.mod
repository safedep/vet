module example.com/app

go 1.22

require (
	example.com/upstream v1.0.0
	example.com/local v1.0.0
	example.com/plain v1.2.0
)

replace example.com/upstream => example.com/fork v1.1.0

replace example.com/local => ./local
