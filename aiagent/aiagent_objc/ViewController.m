#import "ViewController.h"

@interface ViewController ()

@property (nonatomic, strong) NSTextView *chatView;
@property (nonatomic, strong) NSTextField *inputField;
@property (nonatomic, strong) NSButton *sendButton;
@property (nonatomic, strong) NSMutableArray *chatHistory;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.chatHistory = [NSMutableArray array];

    self.view = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 600, 400)];

    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(10, 50, 580, 340)];
    scrollView.hasVerticalScroller = YES;
    self.chatView = [[NSTextView alloc] initWithFrame:scrollView.bounds];
    self.chatView.editable = NO;
    self.chatView.font = [NSFont userFixedPitchFontOfSize:12.0];
    scrollView.documentView = self.chatView;
    [self.view addSubview:scrollView];

    self.inputField = [[NSTextField alloc] initWithFrame:NSMakeRect(10, 10, 480, 30)];
    self.inputField.target = self;
    self.inputField.action = @selector(sendMessage);
    [self.view addSubview:self.inputField];

    self.sendButton = [[NSButton alloc] initWithFrame:NSMakeRect(500, 10, 80, 30)];
    self.sendButton.title = @"Send";
    self.sendButton.bezelStyle = NSBezelStyleRounded;
    self.sendButton.target = self;
    self.sendButton.action = @selector(sendMessage);
    [self.view addSubview:self.sendButton];
}

- (void)sendMessage {
    NSString *userMessage = self.inputField.stringValue;
    if (userMessage.length == 0) {
        return;
    }

    [self appendMessage:[NSString stringWithFormat:@"You: %@\n\n", userMessage]];
    [self.chatHistory addObject:@{@"role": @"user", @"content": userMessage}];
    self.inputField.stringValue = @"";

    self.sendButton.enabled = NO;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self getBotResponse];
    });
}

- (void)getBotResponse {
    NSError *error = nil;
    NSDictionary *requestBody = @{@"messages": self.chatHistory};
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestBody options:0 error:&error];

    NSURL *url = [NSURL URLWithString:@"http://us.fairyao.site/chat"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    request.HTTPBody = jsonData;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendMessage:[NSString stringWithFormat:@"Bot: Error: %@\n\n", error.localizedDescription]];
                self.sendButton.enabled = YES;
            });
            return;
        }

        NSError *jsonError = nil;
        NSDictionary *jsonResponse = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendMessage:@"Bot: Error parsing server response.\n\n"];
                self.sendButton.enabled = YES;
            });
            return;
        }

        NSString *botMessage = jsonResponse[@"response"];
        if (botMessage) {
            [self.chatHistory addObject:@{@"role": @"assistant", @"content": botMessage}];
            dispatch_async(dispatch_get_main_queue(), ^{
                [self appendMessage:[NSString stringWithFormat:@"Bot: %@\n\n", botMessage]];
                self.sendButton.enabled = YES;
            });
        }
    }];
    [task resume];
}

- (void)appendMessage:(NSString *)message {
    [self.chatView.textStorage appendAttributedString:[[NSAttributedString alloc] initWithString:message]];
    [self.chatView scrollRangeToVisible:NSMakeRange(self.chatView.string.length, 0)];
}

@end
