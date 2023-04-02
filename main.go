package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

type CloudTrailEvent struct {
	EventVersion    string `json:"eventVersion"`
	EventID         string `json:"eventID"`
	EventTime       string `json:"eventTime"`
	AWSRegion       string `json:"awsRegion"`
	SourceIPAddress string `json:"sourceIPAddress"`
}

func main() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	cloudTrailSvc := cloudtrail.NewFromConfig(cfg)
	//s3Svc := s3.NewFromConfig(cfg)

	params := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(time.Now().Add(-24 * time.Hour)),
		EndTime:   aws.Time(time.Now()),
	}

	paginator := cloudtrail.NewLookupEventsPaginator(cloudTrailSvc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			log.Fatalf("failed to get events, %v", err)
		}

		for _, event := range page.Events {
			if strings.Contains(*event.EventName, "Login") {
				//if *event.EventName == "ConsoleLogin" {
				fmt.Printf("Event ID: %s\n", *event.EventId)
				fmt.Printf("Username: %s\n", *event.Username)
				fmt.Printf("Event Time: %s\n", event.EventTime.Format(time.RFC3339))

				// Extract IP address from CloudTrail event
				var cloudTrailEvent CloudTrailEvent
				err := json.Unmarshal([]byte(*event.CloudTrailEvent), &cloudTrailEvent)
				if err != nil {
					log.Fatalf("failed to parse CloudTrail event, %v", err)
				}

				ipAddress := cloudTrailEvent.SourceIPAddress
				fmt.Printf("IP Address: %s\n", ipAddress)
				fmt.Println()
			}
		}
	}
}
