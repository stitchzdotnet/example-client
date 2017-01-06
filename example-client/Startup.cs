using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(example_client.Startup))]
namespace example_client
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
