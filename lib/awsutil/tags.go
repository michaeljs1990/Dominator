package awsutil

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"strings"
)

func (tag Tag) makeFilter() *ec2.Filter {
	if tag.Key == "" {
		return nil
	}
	if tag.Value == "" {
		return &ec2.Filter{
			Name:   aws.String("tag-key"),
			Values: aws.StringSlice([]string{tag.Key}),
		}
	} else {
		return &ec2.Filter{
			Name:   aws.String("tag:" + tag.Key),
			Values: aws.StringSlice([]string{tag.Value}),
		}
	}
}

func (tag *Tag) string() string {
	return tag.Key + ":" + tag.Value
}

func (tag *Tag) set(value string) error {
	splitValue := strings.Split(value, ":")
	if len(splitValue) != 2 {
		return errors.New(`malformed tag: "` + value + `"`)
	}
	*tag = Tag{splitValue[0], splitValue[1]}
	return nil
}

func (tags Tags) makeFilters() []*ec2.Filter {
	if len(tags) < 1 {
		return nil
	}
	filters := make([]*ec2.Filter, 0, len(tags))
	for key, value := range tags {
		filters = append(filters, Tag{key, value}.makeFilter())
	}
	return filters
}

func (tags *Tags) string() string {
	pairs := make([]string, 0, len(*tags))
	for key, value := range *tags {
		pairs = append(pairs, key+":"+value)
	}
	return strings.Join(pairs, ",")
}

func (tags *Tags) set(value string) error {
	newTags := make(Tags)
	if value == "" {
		*tags = newTags
		return nil
	}
	for _, tag := range strings.Split(value, ",") {
		splitTag := strings.Split(tag, ":")
		if len(splitTag) != 2 {
			return errors.New(`malformed tag: "` + tag + `"`)
		}
		if splitTag[0] == "" {
			return errors.New("empty tag key")
		}
		newTags[splitTag[0]] = splitTag[1]
	}
	*tags = newTags
	return nil
}
