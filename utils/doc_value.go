package utils

import "fmt"

type DocValue string

func (d *DocValue) String() string {
	return fmt.Sprint(*d)
}

func (d *DocValue) Set(value string) error {
	*d = DocValue(value)
	return nil
}

type DocInclude []string

// Value ...
func (i *DocInclude) String() string {
	return fmt.Sprint(*i)
}

// Set 方法是flag.Value接口, 设置flag Value的方法.
// 通过多个flag指定的值， 所以我们追加到最终的数组上.
func (i *DocInclude) Set(value string) error {
	*i = append(*i, value)
	return nil
}
